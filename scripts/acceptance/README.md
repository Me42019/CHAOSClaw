# Unattended Norman acceptance for IAOS #76

The runner exercises Gate 1 offloading and Gate 2 active-turn masking
through the unchanged Gate 2 Gateway. It submits one synthetic inventory
audit with 14 distinct sequential reads. The first read exceeds the
standard result cap. The second starts inline and ages into a masked
reference. After reading the remaining records, Norman must use both
references to retrieve exact middle ranges and report the recovered seals
and the two hold records. The audit compares tool returns, disk artifacts
and the persisted final reply with deterministic fixtures.

Historical checkpoint analysis is in [the context audit](HISTORICAL-CONTEXT-AUDIT.md).
The previous +5,960 was a calibrated estimate across one large read
before compaction. That experimental compactor and its LFM route are
outside this runner.

## Preparation and verification

Run from a clean checkout of this draft. Linux, Python 3.11 or newer,
aiohttp, Bubblewrap, an offline Cargo cache and the repository toolchain
are required. The host checks target the current CHAOS layout.

```sh
python scripts/acceptance/norman_acceptance.py
mkdir -p "$PWD/../norman-evidence"
python scripts/acceptance/norman_acceptance.py --prepare \
  --evidence-parent "$PWD/../norman-evidence"
```

The first command prints an offline plan. The second builds a
Bubblewrap-enabled candidate with locked dependencies and records the
source commit, exact tree, Rust version, build command and binary SHA-256.
An optional `--target-dir PATH` reuses a dedicated Cargo build cache.
The runner rejects source changes outside this directory relative to the
reviewed base and requires the live checkout to match the prepared
candidate's provenance. Copy the printed preparation directory into
`PREPARED` for the offline tests.

```sh
GATE4_TEST_CANDIDATE="$PREPARED/zeroclaw-candidate" \
  python -m unittest discover -s scripts/acceptance -v
```

The four offline unit checks and two relay checks require no binary. The
three Gateway tests use a scripted localhost server and fake resource
samples. They verify complete exact recovery and durable evidence, a
deadline during a delayed request, and a synthetic OOM change during a
delayed request. No model is involved.

## Later owner-authorized live run

Use this command only after explicit owner approval for one Norman turn.

```sh
python scripts/acceptance/norman_acceptance.py --live \
  --authorize-live I_AUTHORIZE_ONE_NORMAN_RUN \
  --candidate "$PREPARED" --evidence-parent "$PWD/../norman-evidence" \
  --deadline 420
```

The runner reads Norman's route and relevant profile settings from the
installed configuration and verifies the router's window and parallelism.
The current route resolves to a 65,536-token window and a 32,000-token
soft budget from CHAOSClaw's legacy default for an unset profile limit.
That number coincides with the old test, whose explicit compaction
trigger and output reserve do not apply. The production route and router
currently specify no explicit generation cap. The report preserves the
actual completion request limit if the client sends one. Iteration,
response size and wall-clock limits bound the harness independently. The
final Gateway frame cross-checks the effective route and both limits.

The candidate has a separate paired loopback listener, private HOME and
XDG paths, fresh SQLite session, workspace and artifact directory. The
agent's allowlist permits exactly the two read tools under a workspace-only
Bubblewrap policy. The relay requires an ephemeral bearer token and
permits only authenticated, single-flight Norman chat completions with
those two schemas. It forwards neither that token nor production secrets.
Production observations use HTTP GET, kernel counters and a read-only
SQLite connection. Cleanup closes the relay and terminates only the
candidate process group.

The runner checks idle slots before dispatch, the production session
count, generation processes, the single-model router flag, and residency.
An advisory lock excludes other copies of the runner. Each request and
one-second sampling check can stop the run for competing work, restart,
unexpected residency, changed OOM count, RAM/swap/PSI/zram pressure or low
VRAM on the configured discrete GPU. The separately configured CPU-only
embedding service is permitted. Health and slot checks are sampled.
Uncoordinated callers to the same router can race between samples, so the
owner should leave other inference clients idle during the run. The runner
never asks the router to unload a model. Postflight records whether the
router and the original production Gateway are healthy and idle.

## Evidence and interpretation

Each run prints a distinct private evidence directory with the following
files where the run reached the relevant stage.

| Evidence file | Contents |
| --- | --- |
| `report.json` | PASS (exit 0), PARTIAL (2) or FAIL (1), reason, provenance, recovery result and resource/accounting summary. Incomplete state is written before candidate launch. |
| `requests.jsonl` | Per-attempt normalized JSON byte accounting and summed bytes/4 token estimates by system/developer instructions, user/assistant text, reasoning, call envelopes, schemas, tool bodies, framing, previews and masks. Per-row ephemeral keyed fingerprints detect duplicates without retaining displayable content. |
| `responses.jsonl` | Actual input, output and cached input usage when reported, plus latency and any supplied timings. Actual counts are never filled with estimates. A separate residual compares the reported delta with the estimated delta scaled by the previous reported/estimated ratio. |
| `tools.jsonl` | Executed read/recovery sequence, paired results and visible versus original byte lengths. |
| `resources.jsonl`, `router.jsonl`, `lifecycle.jsonl` | Resource samples and stop details, normalized model load/prefill timing from the router journal, and candidate lifecycle. |
| `config/`, `fixtures/`, `runtime.jsonl`, `candidate-gateway.log` | Private synthetic evidence. Artifacts and the Gateway transcript remain under `config/`. Request payload and tool I/O logging are disabled. Keep the private directory local. |

The relay measures the actual chat-completions message population after
Gateway/provider adapter preparation. Its re-encoded JSON byte categories
add up exactly within that encoding. They are an estimate of the model's
chat-template input. The prior ratio can over- or under-predict after
content changes. Consequently an unexplained residual is an alert for
review, not proof of duplicated history. The first response and any
response without actual counts leave residual fields empty as applicable.
The fixture also reports the byte saving relative to keeping the known
original bodies inline. This same-population comparison requires one live
turn. Gate 2's original Rust fixture provides the independent
counterfactual with the runtime estimator.

PASS requires the exact result, both bounded recoveries, durable artifact
matches, paired single execution, a mask, correct route and limits,
complete usage/latency evidence, and healthy postflight with no growth or
repetition alerts. Incomplete metering or anomalous growth yields PARTIAL.
Deadline or interruption yields PARTIAL with the saved prefix.
Guard violations and incorrect execution yield FAIL. A connection close
stops the candidate side immediately. Shared-router cancellation and
resource recovery are observed at postflight.
