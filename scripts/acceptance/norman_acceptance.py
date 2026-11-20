#!/usr/bin/env python3
"""Prepare or run one bounded Norman turn. Default mode is offline planning."""
import argparse
import asyncio
from collections import Counter
from contextlib import suppress
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time

import aiohttp
from aiohttp import web

from norman_accounting import Accounting, ARCHIVE, MASK, TOOLS
from norman_host import MODEL, ROUTER, MIB, Stop, get, resolve, router_timings, sample, stop_reason


BASE = "7b5e091126326b22c1b12ce390ddb0a4fc0c8319"
REPO = Path(__file__).resolve().parents[2]
RUN_ID = "gate4-synthetic"
RECORDS = 14
BUILD = ["cargo", "build", "--offline", "--locked", "-j", "4",
         "--features", "sandbox-bubblewrap", "--bin", "zeroclaw"]
MAX_REQUESTS = 24


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Evidence:
    def __init__(self, parent):
        self.root = Path(tempfile.mkdtemp(prefix="norman-gate4-", dir=parent))

    def emit(self, name, row):
        with (self.root / f"{name}.jsonl").open("a") as log:
            print(json.dumps({"at": utc(), **row}, allow_nan=False), file=log)

    def report(self, row):
        temp = self.root / "report.tmp"
        temp.write_text(json.dumps(row, indent=2) + "\n")
        temp.replace(self.root / "report.json")


def git(*args):
    return subprocess.check_output(["git", *args], cwd=REPO, text=True).strip()


def clean_source():
    if git("status", "--porcelain", "--untracked-files=all"):
        raise Stop("commit_runner_and_use_a_clean_worktree")
    changed = git("diff", "--name-only", BASE, "HEAD").splitlines()
    if any(not path.startswith("scripts/acceptance/") for path in changed):
        raise Stop("candidate_runtime_differs_from_reviewed_gate2")
    if subprocess.run(["git", "merge-base", "--is-ancestor", BASE, "HEAD"], cwd=REPO).returncode:
        raise Stop("candidate_base_differs_from_reviewed_gate2")
    return {"reviewed_base": BASE, "source_commit": git("rev-parse", "HEAD"),
            "source_tree": git("rev-parse", "HEAD^{tree}")}


def prepare(evidence, target):
    row = clean_source()
    target = target or evidence.root / "target"
    version = subprocess.check_output(["rustc", "-Vv"], text=True)
    with (evidence.root / "build.log").open("w") as log:
        command = BUILD + ["--target-dir", str(target)]
        log.write(f"cwd={REPO}\ncommand={command!r}\n{version}\n")
        log.flush()
        subprocess.run(command, cwd=REPO, stdout=log, stderr=subprocess.STDOUT, check=True,
                       env={**os.environ, "CARGO_PROFILE_DEV_DEBUG": "0"})
    if clean_source() != row:
        raise Stop("source_changed_during_build")
    candidate = evidence.root / "zeroclaw-candidate"
    shutil.copy2(target / "debug/zeroclaw", candidate)
    row.update(binary_sha256=file_digest(candidate), build=command, rustc=version,
               dev_debug=0)
    (evidence.root / "candidate.json").write_text(json.dumps(row, indent=2) + "\n")
    return row


def file_digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def candidate_from(prepared):
    row = json.loads((prepared / "candidate.json").read_text())
    binary = prepared / "zeroclaw-candidate"
    if binary.is_symlink() or not binary.is_file() or any(
            row.get(key) != value for key, value in clean_source().items()):
        raise Stop("prepared_candidate_source_mismatch")
    if file_digest(binary) != row["binary_sha256"]:
        raise Stop("prepared_candidate_digest_mismatch")
    return binary, row


def fixtures(root):
    root.mkdir()
    rendered = {}
    ranges = {}
    for n in range(1, RECORDS + 1):
        rows = [f"Inventory {n:02d}"]
        length = 625 if n == 1 else 58 + n
        for i in range(length):
            fragment = digest(f"gate4-inventory:{n}:{i}".encode())[:38]
            if i == length // 2 and n in (1, 2):
                rows.append(f"Receipt seal {n}: {fragment}")
            else:
                rows.append(f"component-{n:02d}-{i:03d} routing=R{i % 17} "
                            f"checksum={fragment} integrity=verified")
        rows.append("Disposition: HOLD" if n in (4, 11) else "Disposition: CLEAR")
        name = f"record-{n:02d}.txt"
        (root / name).write_text("\n".join(rows) + "\n")
        output = "\n".join(f"{i}: {line}" for i, line in enumerate(rows, 1))
        rendered[name] = (output + f"\n[{len(rows)} lines total]").encode()
        if n in (1, 2):
            marker = rows[1 + length // 2]
            ranges[n] = (output.index(marker), len(marker), marker.split(": ")[1])
    return rendered, ranges


def prompt(ranges):
    a, b = ranges[1], ranges[2]
    return (
        "Audit fourteen synthetic inventory records sequentially, record-01.txt through record-14.txt. "
        "Call file_read exactly once per record, one tool per reply, with path only. "
        "Track the two-digit record numbers with Disposition: HOLD from records 03 through 14. "
        "Record 01 returns a compact archive preview. After all fourteen reads, recover its receipt "
        "and then the receipt from the older masked record 02, using each record's artifact reference "
        "with tool_output_read. Use exactly one call per receipt. For record 01 use offset "
        f"{a[0]} and length {a[1]}. For record 02 use offset {b[0]} and length {b[1]}. "
        "These are byte ranges in the original tool results. Never repeat a read. "
        "Finish with exactly READS=14; HOLD=nn,nn; RECEIPTS=seal1,seal2 using the recovered values."
    )


def toml_lines(data):
    return "\n".join(f"{key} = {json.dumps(value)}" for key, value in data.items())


def configuration(root, gateway_port, proxy_port, route, profile, gateway_token, proxy_token):
    config = root / "config"
    (config / "shared" / "skills").mkdir(parents=True)
    pruning = profile.get("history_pruning")
    profile = {k: v for k, v in profile.items() if k != "history_pruning"}
    (config / "config.toml").write_text(f"""schema_version = 4

[gateway]
host = "127.0.0.1"
port = {gateway_port}
require_pairing = true
paired_tokens = ["{digest(gateway_token.encode())}"]
session_persistence = true

[memory]
backend = "none"
auto_save = false
response_cache_enabled = false

[observability]
backend = "none"
log_persistence = true
log_tool_io = "off"
log_llm_request_payload = "off"
log_persistence_path = {json.dumps(str(root / "runtime.jsonl"))}

[reliability]
provider_retries = 0

[tools]
optional = ["tool_output_read"]

[agents.norman]
enabled = true
model_provider = "llamacpp.norman"
risk_profile = "acceptance"
runtime_profile = "acceptance"
delegate_same_risk_profile = false

[agents.norman.workspace]
path = {json.dumps(str(root / "fixtures"))}

[risk_profiles.acceptance]
level = "readonly"
workspace_only = true
allowed_tools = ["file_read", "tool_output_read"]
auto_approve = ["file_read", "tool_output_read"]
sandbox_enabled = true
sandbox_backend = "bubblewrap"
block_high_risk_commands = true

[runtime_profiles.acceptance]
parallel_tools = false
{toml_lines(profile)}

[providers.models.llamacpp.norman]
{toml_lines({**route, "uri": f"http://127.0.0.1:{proxy_port}/v1", "api_key": proxy_token})}
""" + ("\n[runtime_profiles.acceptance.history_pruning]\n" + toml_lines(pruning) + "\n"
       if pruning else ""))
    return config


def allowed_request(payload):
    return (payload["model"] == MODEL and 0 < len(payload["messages"]) <= 48
            and sorted(tool["function"]["name"] for tool in payload["tools"]) == sorted(TOOLS)
            and all(m["role"] in ("developer", "system", "assistant", "user", "tool")
                    for m in payload["messages"]))


class Relay:
    """Pass through the candidate's only generation endpoint, without retries."""
    def __init__(self, evidence, client, token, before_request, upstream=ROUTER, inspect_request=None):
        self.evidence = evidence
        self.client = client
        self.token = bearer(token)["Authorization"]
        self.before_request = before_request
        self.upstream = upstream
        self.inspect_request = inspect_request
        self.accounting = Accounting()
        self.active = False
        self.stopping = False
        self.failure = asyncio.get_running_loop().create_future()
        self.requests = []
        self.responses = []

    async def start(self):
        app = web.Application(client_max_size=MIB)
        app.router.add_post("/v1/chat/completions", self.relay)
        self.runner = web.AppRunner(app, access_log=None, handler_cancellation=True,
                                    shutdown_timeout=2)
        await self.runner.setup()
        sock = socket.socket()
        try:
            sock.bind(("127.0.0.1", 0))
            await web.SockSite(self.runner, sock).start()
            return sock.getsockname()[1]
        except BaseException:
            sock.close()
            await self.runner.cleanup()
            raise

    async def relay(self, request):
        if not hmac.compare_digest(request.headers.get("Authorization", ""), self.token):
            return web.Response(status=401)
        if self.stopping or self.active or self.failure.done() or len(self.requests) >= MAX_REQUESTS:
            if not self.failure.done():
                self.failure.set_result("unexpected_provider_dispatch")
            return web.Response(status=409)
        self.active = True
        try:
            await self.before_request()
            body = await request.read()
            payload = json.loads(body)
            if not allowed_request(payload):
                raise Stop("unexpected_provider_route_or_tools")
            original_bytes = self.inspect_request(payload) if self.inspect_request else {}
            accounting = self.accounting.request(payload, original_bytes)
            self.requests.append(accounting)
            self.evidence.emit("requests", accounting)
            return await self.forward(request, body, accounting)
        except asyncio.CancelledError:
            raise
        except Exception as err:
            if not self.failure.done():
                self.failure.set_result(str(err) if isinstance(err, Stop) else "provider_transport_or_schema_error")
            return web.Response(status=502)
        finally:
            self.active = False

    async def forward(self, request, body, accounting):
        started = time.monotonic()
        url = self.upstream + "/v1/chat/completions"
        response_data = {}
        result = None
        first_data_ms = None
        try:
            async with self.client.post(url, data=body, headers={"Content-Type": "application/json"},
                                        allow_redirects=False) as upstream:
                if upstream.status != 200:
                    raise Stop(f"provider_http_{upstream.status}")
                if upstream.content_type != "text/event-stream":
                    raw = await read_bounded(upstream.content)
                    response_data = json.loads(raw)
                    check_provider_reply(response_data)
                    return web.Response(body=raw, content_type=upstream.content_type)
                result = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
                await result.prepare(request)
                size = 0
                async for line in upstream.content:
                    size += len(line)
                    if size > MIB:
                        raise Stop("provider_response_size_limit")
                    if line.startswith(b"data:"):
                        first_data_ms = first_data_ms or round((time.monotonic() - started) * 1000)
                        value = line[5:].strip()
                        if value and value != b"[DONE]":
                            part = json.loads(value)
                            check_provider_reply(part)
                            for key in ("usage", "timings"):
                                if part.get(key):
                                    response_data[key] = part[key]
                    await result.write(line)
                await result.write_eof()
                return result
        finally:
            usage = self.accounting.usage(accounting, response_data)
            usage.update(wall_ms=round((time.monotonic() - started) * 1000),
                         first_data_ms=first_data_ms)
            self.responses.append(usage)
            self.evidence.emit("responses", usage)


def check_provider_reply(part):
    if part.get("error") or part.get("model", MODEL) != MODEL:
        raise Stop("provider_response_route_or_error")
    if any(c.get("finish_reason") in ("length", "content_filter") for c in part.get("choices", [])):
        raise Stop("provider_stopped_before_completion")
    if part.get("truncated") is True:
        raise Stop("provider_truncated_prompt")


async def read_bounded(stream):
    result = bytearray()
    async for chunk in stream.iter_chunked(65536):
        result.extend(chunk)
        if len(result) > MIB:
            raise Stop("provider_response_size_limit")
    return bytes(result)


class ToolTrail:
    def __init__(self, rendered, ranges, evidence):
        self.rendered, self.ranges, self.evidence = rendered, ranges, evidence
        self.files = list(rendered)
        self.calls = {}
        self.results = set()
        self.archive = None
        self.mask = None
        self.recovered = set()
        self.masked_sources = set()
        self.frames = Counter()

    def observe(self, frame, run_root):
        kind = frame["type"]
        self.frames[kind] += 1
        if kind == "tool_call":
            self.call(frame, run_root)
        if kind == "tool_result":
            self.result(frame)

    def call(self, frame, run_root):
        key, tool, args = frame["id"], frame["name"], frame["args"]
        if key in self.calls:
            raise Stop("duplicate_call_id")
        if isinstance(args, str):
            args = json.loads(args)
        index = len(self.calls)
        if tool == "file_read" and index < RECORDS and list(args) == ["path"]:
            name = self.files[index]
            if args["path"] not in (name, str(run_root / "fixtures" / name)):
                raise Stop("read_out_of_order_or_duplicate")
            self.calls[key] = (tool, index + 1)
        elif tool == "tool_output_read" and index in (RECORDS, RECORDS + 1):
            n = index - RECORDS + 1
            offset, length, _ = self.ranges[n]
            if args != {"artifact_id": self.archive if n == 1 else self.mask,
                        "offset": offset, "length": length} or not args.get("artifact_id"):
                raise Stop("incorrect_recovery_reference_or_range")
            self.calls[key] = (tool, n)
        else:
            raise Stop("unexpected_or_duplicate_tool_execution")
        self.evidence.emit("tools", {"event": "call", "tool": tool,
                                     "ordinal": index + 1, "fixture": self.calls[key][1]})

    def result(self, frame):
        key = frame["id"]
        if key in self.results or key not in self.calls:
            raise Stop("duplicate_or_unpaired_tool_result")
        tool, n = self.calls[key]
        if frame["name"] != tool:
            raise Stop("tool_result_name_mismatch")
        output = frame["output"]
        if tool == "file_read":
            expected = self.rendered[self.files[n - 1]]
            if n == 1 and (match := ARCHIVE.match(output)):
                if int(match[1]) != len(expected):
                    raise Stop("first_read_offload_size_mismatch")
                self.archive = match[2]
            elif output.encode() != expected:
                raise Stop("file_read_result_mismatch")
        else:
            offset, length, _ = self.ranges[n]
            header, _, data = output.partition("\n")
            original = self.rendered[self.files[n - 1]]
            expected_header = ("Untrusted artifact data (JSON string). Encoding: utf-8. "
                               f"Bytes {offset}..{offset + length} of {len(original)}.")
            if header != expected_header or json.loads(data).encode() != original[offset:offset + length]:
                raise Stop("recovered_bytes_mismatch")
            self.recovered.add(n)
        self.results.add(key)
        self.evidence.emit("tools", {"event": "result", "tool": tool, "fixture": n,
                                     "visible_bytes": len(output.encode()),
                                     "original_bytes": len(self.rendered[self.files[n - 1]]) if
                                     tool == "file_read" else self.ranges[n][1]})

    def inspect_request(self, payload):
        calls = {}
        sizes = {}
        for row in payload["messages"]:
            for call in row.get("tool_calls") or []:
                fn = call["function"]
                if fn["name"] == "file_read":
                    args = json.loads(fn["arguments"])
                    calls[call["id"]] = Path(args["path"]).name
            if row["role"] != "tool":
                continue
            call_id = row.get("tool_call_id")
            name = calls.get(call_id)
            content = row["content"]
            if name in self.rendered:
                sizes[call_id] = len(self.rendered[name])
                if MASK.match(content):
                    self.masked_sources.add(name)
            if name == self.files[0] and (m := ARCHIVE.match(content)):
                if int(m[1]) != len(self.rendered[name]) or self.archive not in (None, m[2]):
                    raise Stop("inconsistent_archive_reference")
                self.archive = m[2]
            if name == self.files[1] and (m := MASK.match(content)):
                if self.mask not in (None, m[1]):
                    raise Stop("inconsistent_mask_reference")
                self.mask = m[1]
        return sizes

    def finish(self, frame):
        return (self.recovered == {1, 2} and len(self.results) == RECORDS + 2
                and self.final_text_matches(frame.get("full_response", "")))

    def final_text_matches(self, text):
        return text.strip() == (
            f"READS=14; HOLD=04,11; RECEIPTS={self.ranges[1][2]},{self.ranges[2][2]}")


async def websocket(client, gateway, token, work, trail):
    async with client.ws_connect(
        gateway + "/ws/chat", params={"agent": "norman", "session_id": RUN_ID},
        headers=bearer(token), heartbeat=10, max_msg_size=2 * MIB,
    ) as ws:
        for want, send in (
            ("session_start", {"type": "connect"}),
            ("connected", {"type": "message", "content": prompt(trail.ranges)}),
        ):
            frame = await ws.receive_json()
            if frame["type"] != want or frame.get("resumed") or frame.get("message_count"):
                raise Stop("isolated_websocket_handshake_failed")
            await ws.send_json(send)
        async for event in ws:
            if event.type != aiohttp.WSMsgType.TEXT:
                raise Stop("isolated_websocket_interrupted")
            frame = json.loads(event.data)
            trail.observe(frame, work)
            if frame["type"] in ("done", "error", "aborted", "approval_request"):
                return frame
        raise Stop("isolated_websocket_closed")


def isolated_env(work):
    mapping = {key: work / label for key, label in (
        ("HOME", "home"), ("XDG_DATA_HOME", "data-home"), ("XDG_CONFIG_HOME", "config-home"),
        ("XDG_CACHE_HOME", "cache-home"), ("XDG_STATE_HOME", "state-home"),
        ("XDG_RUNTIME_DIR", "runtime-home"), ("TMPDIR", "tmp"),
    )}
    for path in mapping.values():
        path.mkdir(mode=0o700)
    return {**{key: str(path) for key, path in mapping.items()},
            "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


def private_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    if port in (18083, 42617):
        raise Stop("candidate_port_collides_with_production")
    return port


async def boot(client, process, gateway):
    for _ in range(60):
        if process.returncode is not None:
            raise Stop("candidate_gateway_exited_during_startup")
        try:
            health = await get(client, gateway, "/health")
        except (aiohttp.ClientConnectionError, asyncio.TimeoutError):
            health = {}
        if health.get("status") == "ok":
            if (health["runtime"]["pid"] != process.pid or not health["require_pairing"]
                    or not health["paired"]):
                raise Stop("candidate_listener_identity_mismatch")
            return
        await asyncio.sleep(0.2)
    raise Stop("candidate_gateway_startup_timeout")


async def stop_process(process):
    if process is not None and process.returncode is None:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), 4)
        except asyncio.TimeoutError:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            await process.wait()


class Guard:
    def __init__(self, evidence, probe):
        self.evidence = evidence
        self.probe = probe
        self.lock = asyncio.Lock()
        self.baseline = None
        self.samples = []
        self.strikes = 0

    async def check(self, phase, busy_ok=False, inspect_slots=True):
        async with self.lock:
            row = await self.probe(inspect_slots)
            self.evidence.emit("resources", {"phase": phase, **row})
            self.samples.append(row)
            self.strikes = self.strikes + 1 if row["memory_psi_full_avg10"] >= 8 else 0
            if reason := stop_reason(row, self.baseline, self.strikes, busy_ok):
                raise Stop(reason)
            if phase == "before_turn":
                self.baseline = row

    async def watch(self, relay):
        while True:
            await self.check("during_turn", busy_ok=relay.active, inspect_slots=not relay.active)
            await asyncio.sleep(1)


async def supervise(turn_task, guard_task, failed):
    done, _ = await asyncio.wait((turn_task, guard_task, failed), return_when=asyncio.FIRST_COMPLETED)
    if failed in done:
        raise Stop(failed.result())
    if guard_task in done:
        guard_task.result()
        raise Stop("resource_guard_exited")
    return turn_task.result()


def durable(work, trail):
    directory = work / "config" / "tool-output-v1"
    # The Gateway persists chat turns. Tool-call/result pairing is verified
    # through WS events, and full offloaded/masked sources live in Gate 1's store.
    files = [p for p in directory.iterdir() if re.fullmatch(r"[0-9a-f]{64}", p.name)]
    written = Counter(file_digest(p) for p in files if not p.is_symlink())
    archived_names = trail.masked_sources | {trail.files[0]}
    wanted = Counter(digest(trail.rendered[name]) for name in archived_names)
    db = work / "config" / "data" / "sessions" / "sessions.db"
    if not db.exists():
        return False
    with sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True) as connection:
        rows = connection.execute(
            "SELECT role, content FROM sessions WHERE session_key = ? ORDER BY id", (f"gw_{RUN_ID}",)
        ).fetchall()
    return (not (wanted - written) and trail.files[1] in archived_names
            and [role for role, _ in rows] == ["user", "assistant"]
            and trail.final_text_matches(rows[-1][1]))


async def live(evidence, binary, provenance, deadline, *, route_settings=None, probe=None,
               upstream=ROUTER, timing_reader=router_timings):
    work = evidence.root
    route, profile, expected_budget = route_settings or resolve()
    (rendered, ranges) = fixtures(work / "fixtures")
    trail = ToolTrail(rendered, ranges, evidence)
    gateway_token = "zc_" + secrets.token_hex(32)
    proxy_token = secrets.token_hex(32)
    window = route["context_window"]
    status, reason = "PARTIAL", "incomplete"
    summary = {"candidate": provenance, "model": MODEL, "model_context_window": window,
               "resolved_soft_prompt_budget": expected_budget, "deadline_secs": deadline,
               "profile": profile, "configured_generation_limit": route.get("max_tokens")}
    evidence.report({"status": status, "reason": reason, **summary})
    start = time.time()
    started_turn = None
    process = relay = None
    tasks = []
    frame = {}
    postflight_ok = False
    incomplete = False
    cancel = asyncio.get_running_loop()
    owner_task = asyncio.current_task()
    for signum in (signal.SIGINT, signal.SIGTERM):
        cancel.add_signal_handler(signum, owner_task.cancel)
    async with aiohttp.ClientSession(trust_env=False, timeout=aiohttp.ClientTimeout(total=None)) as client:
        guard = Guard(evidence, probe or (lambda slots: sample(client, window, slots)))

        async def execute():
            nonlocal relay, process, started_turn
            await guard.check("before_candidate")
            relay = Relay(evidence, client, proxy_token, lambda: guard.check("before_request"),
                          upstream=upstream, inspect_request=trail.inspect_request)
            proxy_port = await relay.start()
            port = private_port()
            gateway = f"http://127.0.0.1:{port}"
            config = configuration(work, port, proxy_port, route, profile, gateway_token, proxy_token)
            with (work / "candidate-gateway.log").open("wb") as log:
                process = await asyncio.create_subprocess_exec(
                    str(binary), "--config-dir", str(config), "--log-level", "info",
                    "gateway", "start", cwd=work, env=isolated_env(work), start_new_session=True,
                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                )
            evidence.emit("lifecycle", {"event": "candidate_start", "pid": process.pid})
            await boot(client, process, gateway)
            await guard.check("before_turn")
            started_turn = time.time()
            tasks.extend((asyncio.create_task(websocket(client, gateway, gateway_token, work, trail)),
                          asyncio.create_task(guard.watch(relay))))
            return await supervise(*tasks, relay.failure)

        try:
            async with asyncio.timeout(deadline):
                frame = await execute()
                if frame["type"] != "done":
                    raise Stop("turn_" + frame["type"])
                if not trail.finish(frame):
                    raise Stop("completion_or_recall_mismatch")
                if (frame.get("provider_ref"), frame.get("last_serving_model") or frame.get("model"),
                    frame.get("max_context_tokens"), frame.get("model_context_window")) != (
                        "llamacpp.norman", MODEL, expected_budget, window):
                    raise Stop("candidate_actual_route_or_context_limits_mismatch")
        except asyncio.TimeoutError:
            incomplete, reason = True, "deadline"
        except asyncio.CancelledError:
            incomplete, reason = True, "runner_interrupted"
        except Stop as err:
            status, reason = "FAIL", str(err)
        except Exception as err:
            status, reason = "FAIL", "runner_" + type(err).__name__
        finally:
            for signum in (signal.SIGINT, signal.SIGTERM):
                cancel.remove_signal_handler(signum)
            if relay is not None:
                relay.stopping = True
            for task in tasks:
                task.cancel()
            await stop_process(process)
            if relay is not None:
                await relay.runner.cleanup()
            await asyncio.gather(*tasks, return_exceptions=True)
            evidence.emit("lifecycle", {"event": "candidate_stopped"})
            if guard.baseline:
                try:
                    await guard.check("after_candidate")
                    postflight_ok = True
                except Exception as err:
                    evidence.emit("lifecycle", {"event": "postflight_failed",
                                                "reason": str(err) if isinstance(err, Stop) else type(err).__name__})
    ended = time.time()
    timing = {"journal_prefill_samples": 0, "model_load_ms": None}
    if started_turn is not None:
        try:
            timing = timing_reader(started_turn, ended, evidence.emit)
        except Exception as err:
            evidence.emit("lifecycle", {"event": "router_timing_unavailable",
                                        "reason": type(err).__name__})
    requests = relay.requests if relay else []
    responses = relay.responses if relay else []
    alerts = Counter(alert for row in requests + responses for alert in row["alerts"])
    cold_start = bool(guard.baseline and guard.baseline["models"][MODEL] == "unloaded")
    if status != "FAIL" and not incomplete:
        try:
            if not durable(work, trail) or not any(r["masked_rows"] for r in requests):
                status, reason = "FAIL", "durable_source_or_mask_unverified"
            elif alerts:
                status, reason = "PARTIAL", "request_growth_or_repetition_alert"
            elif not postflight_ok or not requests or len(responses) != len(requests):
                status, reason = "PARTIAL", "incomplete_health_or_accounting"
            elif (any(r["reported_input_tokens"] is None for r in responses)
                  or (timing["journal_prefill_samples"] < len(requests)
                      and any(r["prefill_ms"] is None for r in responses))
                  or (cold_start and timing["model_load_ms"] is None)):
                status, reason = "PARTIAL", "usage_or_router_timing_unavailable"
            else:
                status, reason = "PASS", "complete_exact_recall_and_preservation"
        except Exception as err:
            status, reason = "FAIL", "durable_audit_" + type(err).__name__
    samples = guard.samples
    if samples:
        summary["resources"] = {
            "min_available_ram_mib": min(s["ram_available_mib"] for s in samples),
            "min_swap_free_mib": min(s["swap_free_mib"] for s in samples),
            "peak_swap_used_mib": max(s["swap_used_mib"] for s in samples),
            "peak_zram_physical_mib": max(s["zram_physical_mib"] for s in samples),
            "peak_memory_psi_full_avg10": max(s["memory_psi_full_avg10"] for s in samples),
            "peak_total_vram_used_mib": max(sum(gpu["used_mib"] for gpu in s["vram"]) for s in samples),
            "oom_kill_delta": samples[-1]["oom_kill"] - samples[0]["oom_kill"],
            "router_generation_limit_flag": samples[0].get("router_generation_limit"),
        }
    summary.update(
        status=status, reason=reason, elapsed_secs=round(ended - start, 3),
        timing={**timing, "cold_start": cold_start,
                "provider_prefill_samples": sum(r["prefill_ms"] is not None for r in responses)},
        dispatched_requests=len(requests), accounted_responses=len(responses),
        dispatched_tool_calls=len(trail.calls), paired_tool_results=len(trail.results),
        masked_fixtures=len(trail.masked_sources),
        maximum_masked_body_bytes_saved=max((r["masked_body_bytes_saved"] for r in requests), default=0),
        request_alerts=dict(alerts), peak_estimate=max((r["estimated_tokens"] for r in requests), default=None),
        peak_reported_input=max((r["reported_input_tokens"] for r in responses
                                 if r["reported_input_tokens"] is not None), default=None),
        frames=dict(trail.frames), recovered_fixture_ordinals=sorted(trail.recovered),
        production_health_and_idle_verified=postflight_ok, ended_at=utc(),
        evidence_dir=str(work),
    )
    evidence.report(summary)
    return summary


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare", action="store_true", help="build and hash an offline candidate")
    mode.add_argument("--live", action="store_true", help="run exactly one owner-authorized live turn")
    parser.add_argument("--authorize-live", choices=["I_AUTHORIZE_ONE_NORMAN_RUN"])
    parser.add_argument("--candidate", type=Path, help="path to a prepared candidate directory")
    parser.add_argument("--target-dir", type=Path, help="optional dedicated offline Cargo target")
    parser.add_argument("--evidence-parent", type=Path, help="existing directory for a new private run")
    parser.add_argument("--deadline", type=int, default=420)
    args = parser.parse_args(argv)
    if args.live and (not args.authorize_live or not args.candidate or not 1 <= args.deadline <= 900):
        parser.error("--live requires --authorize-live, --candidate and a deadline of 1–900 seconds")
    if not args.live and (args.authorize_live or args.candidate):
        parser.error("live options require --live")
    if args.target_dir and not args.prepare:
        parser.error("--target-dir requires --prepare")
    if not args.prepare and not args.live:
        print("DRY RUN. One isolated Norman turn, 14 distinct full reads and 2 exact artifact ranges.")
        return 0
    if not args.evidence_parent:
        parser.error("--prepare and --live require --evidence-parent")
    os.umask(0o077)
    evidence = Evidence(args.evidence_parent.resolve())
    print(str(evidence.root), flush=True)
    try:
        if args.prepare:
            row = prepare(evidence, args.target_dir.resolve() if args.target_dir else None)
            print(json.dumps(row))
            return 0
        binary, row = candidate_from(args.candidate.resolve())
        # Local advisory lock serializes runners using this production router.
        # Other clients are checked by the idle and resource probes.
        import fcntl
        # Lock a private owner-scoped directory in the normal per-user runtime
        # directory. Avoid creating or writing a lock inside production state.
        runtime = Path(f"/run/user/{os.getuid()}")
        lock_dir = runtime / "chaosclaw-norman-acceptance"
        lock_dir.mkdir(mode=0o700, exist_ok=True)
        if lock_dir.is_symlink() or lock_dir.stat().st_uid != os.getuid() or lock_dir.stat().st_mode & 0o077:
            raise Stop("unsafe_runner_lock_directory")
        fd = os.open(lock_dir / "router.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = asyncio.run(live(evidence, binary, row, args.deadline))
        print(f'{result["status"]} {result["reason"]}')
        return {"PASS": 0, "PARTIAL": 2, "FAIL": 1}[result["status"]]
    except Exception as err:
        reason = str(err) if isinstance(err, Stop) else type(err).__name__
        evidence.report({"status": "FAIL", "reason": reason, "evidence_dir": str(evidence.root)})
        print(f"FAIL {reason}")
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
