"""Numeric accounting for the isolated Norman chat-completions request."""
from collections import Counter
import hashlib
import json
import re
import secrets


TOOLS = {"file_read", "tool_output_read"}
ARCHIVE = re.compile(r"^Tool output \(success, (\d+) bytes, \d+ lines\)\. "
                     r"Archived as untrusted data\. tool_output_read artifact_id=([0-9a-f]{64})\.")
MASK = re.compile(r"^Older observation \(success, untrusted data\) hidden\. "
                  r"Recover with tool_output_read \(artifact_id=([0-9a-f]{64}),")


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def count(value):
    return len(value.encode() if isinstance(value, str) else wire(value))


class Accounting:
    def __init__(self):
        self.key = secrets.token_bytes(32)
        self.previous = None
        self.previous_report = None

    def request(self, payload, original_bytes=None):
        original_bytes = original_bytes or {}
        totals = Counter()
        fingerprints = Counter()
        fixed = []
        rows = []
        calls = {}
        for spec in payload["tools"]:
            totals["tool_schemas"] += count(spec)
        for msg in payload["messages"]:
            role = msg["role"]
            item = {"role": role}
            content = msg.get("content") or ""
            category = {"system": "instructions", "developer": "instructions",
                        "assistant": "assistant_text", "user": "user_text",
                        "tool": "tool_results"}.get(role, "other_message_text")
            if role == "tool" and isinstance(content, str):
                if MASK.match(content):
                    category = "masked_references"
                elif match := ARCHIVE.match(content):
                    category = "offloaded_previews"
                    item["original_bytes"] = int(match[1])
            pieces = Counter({category: count(content)})
            for field in ("reasoning_content", "reasoning"):
                if field in msg and msg[field] is not None:
                    pieces["assistant_reasoning"] += count(msg[field])
            if "tool_calls" in msg:
                pieces["tool_calls"] += count(msg["tool_calls"])
                for call in msg["tool_calls"]:
                    calls[call["id"]] = call["function"]["name"]
            if role == "tool":
                item["tool"] = calls.get(msg.get("tool_call_id"))
                if msg.get("tool_call_id") in original_bytes:
                    item["original_bytes"] = original_bytes[msg["tool_call_id"]]
            # Difference includes JSON escaping, keys, role and pairing ID.
            pieces["message_framing"] = count(msg) - pieces.total()
            totals.update(pieces)
            digest = self.fingerprint(msg)
            fingerprints[digest] += 1
            if category == "instructions":
                fixed.append(digest)
            rows.append({**item, "bytes": dict(pieces), "fingerprint": digest})
        fixed.append(self.fingerprint(payload["tools"]))
        totals["request_framing"] = count(payload) - totals.total()
        estimates = {k: (v + 3) // 4 for k, v in totals.items()}
        # Raw JSON is a proxy for prompt size. The server's chat template can
        # omit fields, expand schemas and add tokens absent from this JSON.
        estimate = sum(estimates.values())
        previous = self.previous
        duplicate_rows = sum(n - 1 for n in fingerprints.values())
        alerts = []
        if duplicate_rows:
            alerts.append("duplicate_request_rows")
        population = self.fingerprint((payload["messages"], payload["tools"]))
        if previous and previous["population"] == population:
            alerts.append("repeated_request_population")
        if previous and previous["fixed"] != fixed:
            alerts.append("instruction_or_schema_change")
        if previous and estimate - previous["estimated_tokens"] >= 5000:
            alerts.append("large_estimated_increase")
        result = {
            "request_number": 1 if previous is None else previous["request_number"] + 1,
            "model": payload["model"], "bytes_by_component": dict(totals),
            "estimated_tokens_by_component": estimates, "estimated_tokens": estimate,
            "estimated_delta": None if previous is None else estimate - previous["estimated_tokens"],
            "max_completion_tokens": payload.get("max_completion_tokens", payload.get("max_tokens")),
            "masked_rows": sum("masked_references" in row["bytes"] for row in rows),
            "offloaded_preview_rows": sum("offloaded_previews" in row["bytes"] for row in rows),
            "masked_body_bytes_saved": sum(row.get("original_bytes", 0) - row["bytes"]["masked_references"]
                                            for row in rows if "masked_references" in row["bytes"]
                                            and "original_bytes" in row),
            "duplicate_rows": duplicate_rows, "alerts": alerts, "rows": rows,
        }
        self.previous = {**result, "fixed": fixed, "population": population}
        return result

    def fingerprint(self, value):
        return hashlib.blake2s(wire(value), key=self.key, digest_size=16).hexdigest()

    def usage(self, request, response):
        usage = response.get("usage") or {}
        reported = integer(usage.get("prompt_tokens"))
        estimated = request["estimated_tokens"]
        previous = self.previous_report
        delta = predicted = residual = None
        alerts = []
        if reported is not None:
            self.previous_report = (reported, estimated)
            if previous:
                old_reported, old_estimate = previous
                delta = reported - old_reported
                predicted = round((estimated - old_estimate) * old_reported / max(1, old_estimate))
                residual = delta - predicted
                if residual >= max(1500, abs(predicted) // 2):
                    alerts.append("unexplained_reported_increase")
        timings = response.get("timings") or {}
        return {
            "request_number": request["request_number"],
            "reported_input_tokens": reported,
            "reported_output_tokens": integer(usage.get("completion_tokens")),
            "reported_cached_tokens": integer((usage.get("prompt_tokens_details") or {}).get("cached_tokens")),
            "reported_input_delta": delta, "predicted_reported_delta": predicted,
            "unexplained_growth_tokens": residual, "alerts": alerts,
            "prefill_ms": number(timings.get("prompt_ms")),
            "prefill_evaluated_tokens": integer(timings.get("prompt_n")),
            "generation_ms": number(timings.get("predicted_ms")),
        }


def integer(value):
    return value if type(value) is int and value >= 0 else None


def number(value):
    return value if type(value) in (float, int) and 0 <= value < float("inf") else None
