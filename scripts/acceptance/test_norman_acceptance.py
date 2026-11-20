"""Non-inference tests using a scripted localhost provider and real Gate 2 Gateway."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest

import aiohttp
from aiohttp import web

from norman_acceptance import Evidence, Relay, MODEL, TOOLS, cli, fixtures, live, supervise
from norman_accounting import Accounting, ARCHIVE, MASK, wire
from norman_host import Stop, stop_reason


def request():
    return {
        "model": MODEL,
        "tools": [{"type": "function", "function": {"name": name, "parameters": {"type": "object"}}}
                  for name in sorted(TOOLS)],
        "messages": [{"role": "system", "content": "synthetic private sentinel"},
                     {"role": "user", "content": 'sample with quote " and emoji 🧪'}],
        "stream": True,
    }


def sample():
    return {"gateway_pid": 100, "production_running_turns": 0, "oom_kill": 1,
            "ram_available_mib": 11000, "swap_free_mib": 6000, "swap_used_mib": 2000,
            "zram_physical_mib": 2300, "memory_psi_full_avg10": 0,
            "models": {MODEL: "unloaded"}, "slots": [],
            "vram": [{"total_mib": 16000, "used_mib": 500}]}


class OfflineTests(unittest.TestCase):
    def test_accounting_sums_and_preserves_privacy(self):
        payload = request()
        payload["messages"] += [{"role": "assistant", "content": "assistant text",
                                 "reasoning_content": "reasoning", "tool_calls": [{
                                     "id": "call1", "type": "function", "function": {
                                         "name": "file_read", "arguments": '{"path":"secret"}'}}]},
                                {"role": "tool", "tool_call_id": "call1",
                                 "content": "Older observation (success, untrusted data) hidden. "
                                 f"Recover with tool_output_read (artifact_id={'f' * 64}, offset=0)."}]
        row = Accounting().request(payload)
        self.assertEqual(sum(row["bytes_by_component"].values()), len(wire(payload)))
        self.assertEqual(sum(row["estimated_tokens_by_component"].values()), row["estimated_tokens"])
        self.assertEqual(row["masked_rows"], 1)
        for private in ("private sentinel", "secret", "call1", "f" * 64, "assistant text"):
            self.assertNotIn(private, json.dumps(row))

    def test_residual_separates_estimates_and_actual_usage(self):
        accounting = Accounting()
        p = request()
        a = accounting.request(p)
        self.assertIsNone(accounting.usage(a, {})["reported_input_tokens"])
        accounting.usage(a, {"usage": {"prompt_tokens": 1000}})
        b = accounting.request(p)
        growth = accounting.usage(b, {"usage": {"prompt_tokens": 6960}})
        self.assertEqual(growth["unexplained_growth_tokens"], 5960)
        self.assertIn("unexplained_reported_increase", growth["alerts"])
        self.assertEqual(b["estimated_delta"], 0)
        self.assertIn("repeated_request_population", b["alerts"])
        p["messages"].append(p["messages"][0])
        self.assertIn("duplicate_request_rows", accounting.request(p)["alerts"])

    def test_guard_thresholds_and_conflicts(self):
        baseline = sample()
        cases = [
            ({"production_running_turns": 1}, "production_turn_active"),
            ({"models": {MODEL: "unloaded", "other": "loaded"}}, "unexpected_model_residency"),
            ({"oom_kill": 2}, "oom_counter_changed"),
            ({"ram_available_mib": 4095}, "ram_pressure"),
            ({"swap_free_mib": 383}, "swap_pressure"),
            ({"zram_physical_mib": 3324}, "zram_growth"),
            ({"memory_psi_full_avg10": 8}, "memory_stall_pressure"),
            ({"vram": [{"total_mib": 16000, "used_mib": 15990}]}, "vram_pressure"),
            ({"gateway_pid": 101}, "production_gateway_changed"),
            ({"slots": [{"is_processing": True}]}, "norman_slot_busy"),
        ]
        for patch, expected in cases:
            with self.subTest(expected):
                self.assertEqual(stop_reason({**baseline, **patch}, baseline, strikes=4), expected)

    def test_owner_authorization_is_required_before_creating_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(cli([]), 0)
            with self.assertRaises(SystemExit) as error:
                cli(["--live", "--candidate", d, "--evidence-parent", d])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(list(Path(d).iterdir()), [])


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_guard_wins_even_when_turn_also_finishes(self):
        async def stop():
            raise Stop("oom_counter_changed")
        result = asyncio.create_task(asyncio.sleep(0, result="done"))
        guard = asyncio.create_task(stop())
        failure = asyncio.get_running_loop().create_future()
        with self.assertRaisesRegex(Stop, "oom_counter_changed"):
            await supervise(result, guard, failure)

    async def test_relay_is_closed_to_control_requests_and_foreign_models(self):
        async def noop():
            pass
        with tempfile.TemporaryDirectory() as d:
            async with aiohttp.ClientSession() as client:
                relay = Relay(Evidence(d), client, "test-only", noop, upstream="http://127.0.0.1:1")
                port = await relay.start()
                try:
                    base = f"http://127.0.0.1:{port}"
                    async with client.post(base + "/models/load", json={"model": MODEL}) as r:
                        self.assertEqual(r.status, 404)
                    async with client.post(base + "/v1/chat/completions", json=request()) as r:
                        self.assertEqual(r.status, 401)
                    async with client.post(
                        base + "/v1/chat/completions", json={**request(), "model": "foreign"},
                        headers={"Authorization": "Bearer test-only"},
                    ) as r:
                        self.assertEqual(r.status, 502)
                    self.assertEqual(relay.failure.result(), "unexpected_provider_route_or_tools")
                    self.assertEqual(relay.requests, [])
                finally:
                    await relay.runner.cleanup()


@unittest.skipUnless(os.environ.get("GATE4_TEST_CANDIDATE"), "set GATE4_TEST_CANDIDATE for real Gateway tests")
class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def scripted_run(self, stop=None):
        self.seq = 0
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.evidence = Evidence(os.environ.get("GATE4_TEST_EVIDENCE_PARENT", self.temp.name))
        _, ranges = fixtures(Path(self.temp.name) / "expected")
        route = {"model": MODEL, "wire_api": "chat_completions", "native_tools": True,
                 "context_window": 65536, "timeout_secs": 30}
        profile = {"agentic": True, "max_tool_iterations": 20}
        references = {}

        async def reply(req):
            body = await req.json()
            if self.seq == 0:
                self.assertEqual({t["function"]["name"] for t in body["tools"]}, TOOLS)
                if stop:
                    await asyncio.sleep(8)
            pending = {}
            for m in body["messages"]:
                for c in m.get("tool_calls") or []:
                    pending[c["id"]] = c["function"]
                if m["role"] == "tool":
                    fn = pending[m["tool_call_id"]]
                    if fn["name"] == "file_read":
                        if hit := ARCHIVE.match(m["content"]):
                            references[1] = hit[2]
                        if (hit := MASK.match(m["content"])) and json.loads(fn["arguments"])["path"] == "record-02.txt":
                            references[2] = hit[1]
            self.seq += 1
            if self.seq <= 14:
                name, args = "file_read", {"path": f"record-{self.seq:02}.txt"}
            elif self.seq <= 16:
                n = self.seq - 14
                name, args = "tool_output_read", {"artifact_id": references[n],
                                                 "offset": ranges[n][0], "length": ranges[n][1]}
            else:
                name = None
            final = f"READS=14; HOLD=04,11; RECEIPTS={ranges[1][2]},{ranges[2][2]}"
            call = {"id": f"call_{self.seq:02}", "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args) if name else ""}}
            msg = {"role": "assistant", "content": None if name else final}
            if name:
                msg["tool_calls"] = [call]
            metadata = {"id": f"cmpl-{self.seq}", "model": MODEL, "created": 1}
            usage = {"prompt_tokens": 2000, "completion_tokens": 20, "total_tokens": 2020}
            timings = {"prompt_ms": 10.0, "prompt_n": 100, "predicted_ms": 20.0}
            finish = "tool_calls" if name else "stop"
            if not body.get("stream"):
                return web.json_response({**metadata, "choices": [{"index": 0, "message": msg,
                                          "finish_reason": finish}], "usage": usage, "timings": timings})
            if name:
                call["index"] = 0
            chunks = [{"choices": [{"index": 0, "delta": msg, "finish_reason": finish}]},
                      {"choices": [], "usage": usage, "timings": timings}]
            return web.Response(
                body=b"".join(b"data: " + wire({**metadata, **c}) + b"\n\n" for c in chunks)
                + b"data: [DONE]\n\n", content_type="text/event-stream",
            )

        app = web.Application()
        app.router.add_post("/v1/chat/completions", reply)
        provider = web.AppRunner(app, handler_cancellation=True)
        await provider.setup()
        site = web.TCPSite(provider, "127.0.0.1", 0)
        await site.start()
        upstream = "http://" + provider.addresses[0][0] + f":{provider.addresses[0][1]}"
        count = 0

        async def probe(_slots):
            nonlocal count
            count += 1
            if stop == "oom" and count >= 5:
                return {**sample(), "oom_kill": 2}
            return sample()

        try:
            return await live(self.evidence, Path(os.environ["GATE4_TEST_CANDIDATE"]).resolve(),
                              {"fake_provider": True}, 2 if stop == "deadline" else 18,
                              upstream=upstream, probe=probe, route_settings=(route, profile, 32000),
                              timing_reader=lambda *_: {"journal_prefill_samples": 0, "model_load_ms": 20})
        finally:
            await provider.cleanup()

    async def test_real_gateway_recovers_both_middle_slices_and_keeps_history(self):
        result = await self.scripted_run()
        if result["status"] != "PASS":
            # The failure report carries only synthetic numeric metadata.
            self.fail(json.dumps(result))
        self.assertEqual(result["dispatched_requests"], 17)
        self.assertEqual(result["recovered_fixture_ordinals"], [1, 2])

    async def test_real_gateway_deadline_retains_partial_report(self):
        result = await self.scripted_run(stop="deadline")
        self.assertEqual((result["status"], result["reason"]), ("PARTIAL", "deadline"))
        self.assertGreaterEqual(result["dispatched_requests"], 1)
        self.assertTrue((self.evidence.root / "requests.jsonl").exists())
        self.assertEqual(json.loads((self.evidence.root / "report.json").read_text()), result)

    async def test_real_gateway_resource_guard_stops_delayed_request(self):
        result = await self.scripted_run(stop="oom")
        self.assertEqual((result["status"], result["reason"]), ("FAIL", "oom_counter_changed"))
        self.assertGreaterEqual(result["dispatched_requests"], 1)
