"""Read-only preflight and resource guard for the CHAOS single-model router."""
import asyncio
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import tomllib


ROUTER = "http://127.0.0.1:18083"
GATEWAY = "http://127.0.0.1:42617"
MODEL = "chaos-norman-qwen3-8-27b-iq3m"
PROD_CONFIG = Path.home() / ".config/zeroclaw/config.toml"
PROD_DB = Path.home() / ".local/share/zeroclaw/data/sessions/sessions.db"
MIB = 1024 * 1024
NORMAN_GPU = Path("/sys/bus/pci/devices/0000:03:00.0")


class Stop(RuntimeError):
    """Fixed diagnostic code safe to include in the evidence."""


def resolve(config_path=PROD_CONFIG):
    config = tomllib.loads(config_path.read_text())
    agent = config["agents"]["norman"]
    if agent["model_provider"] != "llamacpp.norman":
        raise Stop("configured_norman_route_changed")
    source = config["providers"]["models"]["llamacpp"]["norman"]
    if (source["uri"], source["model"], source.get("wire_api"), source.get("native_tools")) != (
            ROUTER + "/v1", MODEL, "chat_completions", True):
        raise Stop("configured_norman_route_changed")
    safe_route = ("uri", "model", "wire_api", "native_tools", "context_window",
                  "timeout_secs", "max_tokens")
    if source.keys() - set(safe_route):
        raise Stop("review_changed_norman_provider_fields")
    route = {k: source[k] for k in safe_route if k in source}
    source_profile = config["runtime_profiles"][agent["runtime_profile"]]
    safe_profile = ("agentic", "max_tool_iterations", "max_context_tokens",
                    "context_compact_ratio", "history_pruning", "max_tool_result_chars")
    if source_profile.keys() - set(safe_profile):
        raise Stop("review_changed_norman_profile_fields")
    profile = {k: source_profile[k] for k in safe_profile if k in source_profile}
    if not profile.get("agentic") or not 17 <= profile.get("max_tool_iterations", 0) <= 24:
        raise Stop("norman_iteration_limit_incompatible")
    # Mirrors ResolvedRuntime::context_limits for an explicit model window.
    # The candidate's terminal session metrics independently verify these.
    window = route["context_window"]
    absolute = profile.get("max_context_tokens")
    ratio = profile.get("context_compact_ratio", 0)
    if absolute == 0:
        budget = 0
    else:
        budget = min(max(1, int(window * ratio)), absolute or window) if 0 < ratio <= 1 else (
            32_000 if absolute is None else absolute)
        pruning = profile.get("history_pruning", {})
        if pruning.get("enabled") and pruning.get("max_tokens", 0) > 0:
            budget = min(budget, pruning["max_tokens"])
        budget = min(budget, window)
    return route, profile, budget


def read_active_sessions():
    # Require the existing WAL index. Opening a WAL database read-only while
    # its owner is running also observes committed rows still in the WAL.
    for suffix in ("", "-wal", "-shm"):
        if not Path(f"{PROD_DB}{suffix}").is_file():
            raise Stop("production_session_state_unavailable")
    with sqlite3.connect(f"{PROD_DB.as_uri()}?mode=ro", uri=True, timeout=0.25) as db:
        db.execute("PRAGMA query_only=ON")
        return db.execute("SELECT count(*) FROM session_metadata WHERE state='running'").fetchone()[0]


def llama_processes():
    routers, children, outsiders = [], [], []
    for path in Path("/proc").glob("[0-9]*/comm"):
        try:
            if path.read_text().strip() != "llama-server":
                continue
            directory = path.parent
            cgroup = directory.joinpath("cgroup").read_text()
            args = directory.joinpath("cmdline").read_text().split("\0")
            pid = int(directory.name)
            if "/chaos-embeddinggemma.service" in cgroup and "--embedding" in args and (
                    "--n-gpu-layers" in args and arg(args, "--n-gpu-layers") == "0"):
                continue
            if "/chaos-llama-router.service" not in cgroup:
                outsiders.append(pid)
            elif "--models-max" in args and arg(args, "--models-max") == "1":
                routers.append(pid)
            else:
                info = directory.joinpath("stat").read_text().rsplit(") ", 1)[1].split()
                children.append((pid, int(info[1])))
        except (FileNotFoundError, ProcessLookupError):
            continue
    if len(routers) != 1 or outsiders or len(children) > 1 or any(
            parent != routers[0] for _, parent in children):
        raise Stop("conflicting_llama_process_or_router_parallelism")
    return routers[0], len(children)


def resources():
    mem = {a.rstrip(":"): int(b) for a, b, *_ in
           (line.split() for line in Path("/proc/meminfo").read_text().splitlines())}
    vm = dict(line.split() for line in Path("/proc/vmstat").read_text().splitlines())
    pressure = {line.split()[0]: float(line.split()[1].split("=")[1])
                for line in Path("/proc/pressure/memory").read_text().splitlines()}
    zram = list(Path("/sys/block").glob("zram*/mm_stat"))
    gpu = NORMAN_GPU / "mem_info_vram_total"
    if not zram or not gpu.is_file():
        raise Stop("resource_counters_unavailable")
    router_pid, model_workers = llama_processes()
    return {
        "router_pid": router_pid, "router_model_workers": model_workers,
        "ram_available_mib": mem["MemAvailable"] // 1024,
        "swap_free_mib": mem["SwapFree"] // 1024,
        "swap_used_mib": (mem["SwapTotal"] - mem["SwapFree"]) // 1024,
        "zram_physical_mib": sum(int(p.read_text().split()[2]) for p in zram) // MIB,
        "memory_psi_full_avg10": pressure["full"],
        "oom_kill": int(vm["oom_kill"]),
        "vram": [{"used_mib": int(gpu.with_name("mem_info_vram_used").read_text()) // MIB,
                  "total_mib": int(gpu.read_text()) // MIB}],
        "production_running_turns": read_active_sessions(),
    }


async def get(client, base, path):
    async with client.get(base + path, allow_redirects=False, timeout=3) as response:
        if response.status != 200:
            raise Stop("health_probe_http_error")
        return await response.json(content_type=None)


def arg(args, name):
    return args[args.index(name) + 1]


async def sample(client, window, inspect_slots):
    result = resources()
    # Take health/router samples together so a stalled probe cannot delay a
    # stop decision by the sum of multiple HTTP timeouts.
    gw, router, listing = await asyncio.gather(
        get(client, GATEWAY, "/health"), get(client, ROUTER, "/health"),
        get(client, ROUTER, "/v1/models"),
    )
    result["gateway_pid"] = gw["runtime"]["pid"]
    if gw["status"] != "ok" or router["status"] != "ok":
        raise Stop("production_health_probe_failed")
    statuses = {item["id"]: item["status"] for item in listing["data"]}
    args = statuses[MODEL]["args"]
    if int(arg(args, "--ctx-size")) != window or arg(args, "--parallel") != "1":
        raise Stop("router_context_or_parallelism_mismatch")
    if arg(args, "--device") != "ROCm0":
        raise Stop("router_device_changed")
    result["router_generation_limit"] = (int(arg(args, "--n-predict"))
                                         if "--n-predict" in args else None)
    result["models"] = {name: row["value"] for name, row in statuses.items()}
    result["slots"] = []
    if inspect_slots and statuses[MODEL]["value"] == "loaded":
        port = int(arg(statuses[MODEL]["args"], "--port"))
        if port in (18083, 42617) or not 1024 <= port <= 65535:
            raise Stop("invalid_norman_child_port")
        slots = await get(client, f"http://127.0.0.1:{port}", "/slots")
        if len(slots) != 1 or slots[0]["n_ctx"] != window:
            raise Stop("router_slot_context_or_parallelism_mismatch")
        result["slots"] = [{k: slot[k] for k in ("is_processing", "n_ctx")} for slot in slots]
    return result


def stop_reason(row, baseline=None, strikes=0, busy_ok=False):
    if row["production_running_turns"]:
        return "production_turn_active"
    if any(status != "unloaded" for name, status in row["models"].items() if name != MODEL):
        return "unexpected_model_residency"
    if row["models"][MODEL] not in ({"loaded", "unloaded", "loading"} if busy_ok else {"loaded", "unloaded"}):
        return "unexpected_norman_transition"
    if not busy_ok and any(slot["is_processing"] is not False for slot in row["slots"]):
        return "norman_slot_busy"
    if baseline and row["gateway_pid"] != baseline["gateway_pid"]:
        return "production_gateway_changed"
    if baseline and row.get("router_pid") != baseline.get("router_pid"):
        return "production_router_changed"
    if baseline and row["oom_kill"] != baseline["oom_kill"]:
        return "oom_counter_changed"
    if row["ram_available_mib"] < (4096 if baseline else 6144):
        return "ram_pressure"
    if row["swap_free_mib"] < (384 if baseline else 768):
        return "swap_pressure"
    if row["memory_psi_full_avg10"] >= (2 if baseline else 1) and (
            not baseline or strikes >= 4 or row["ram_available_mib"] < 8192
            or row["swap_free_mib"] < 768):
        return "memory_stall_pressure"
    if baseline and row["zram_physical_mib"] - baseline["zram_physical_mib"] >= 1024:
        return "zram_growth"
    if any(gpu["total_mib"] - gpu["used_mib"] < 128 for gpu in row["vram"]):
        return "vram_pressure"
    return None


def router_timings(started, ended, emit):
    """Fallback for builds that omit timings in the completion body."""
    result = subprocess.run(
        ["journalctl", "--user", "-u", "chaos-llama-router.service", "--no-pager",
         "-o", "json", "--since", f"@{int(started)}", "--until", f"@{int(ended) + 1}"],
        capture_output=True, check=True, timeout=5, text=True,
    )
    load_start = load_ms = None
    prompt = re.compile(r"task (\d+).*?prompt eval time\s*=\s*([\d.]+) ms /\s*(\d+) tokens")
    prefill = 0
    for line in result.stdout.splitlines():
        row = json.loads(line)
        instant = int(row["__REALTIME_TIMESTAMP"]) / 1e6
        msg = row.get("MESSAGE")
        if not started <= instant <= ended or not isinstance(msg, str):
            continue
        if f"ensure_model: waiting until model name={MODEL} is fully loaded" in msg:
            load_start = instant
        if load_start and "server_run_i: model loaded" in msg:
            load_ms = round((instant - load_start) * 1000)
            emit("router", {"event": "model_loaded", "timestamp_unix": instant,
                            "load_ms": load_ms})
            load_start = None
        if match := prompt.search(msg):
            prefill += 1
            emit("router", {"event": "prefill", "timestamp_unix": instant,
                            "router_task": int(match[1]), "prefill_ms": float(match[2]),
                            "prefill_evaluated_tokens": int(match[3])})
    return {"journal_prefill_samples": prefill, "model_load_ms": load_ms}
