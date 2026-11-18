# IAOS #69 within-turn compaction

The runtime shortens older successful native tool results in the provider request once the prepared history estimate exceeds 70% of the selected route’s positive context token budget. It keeps the user objective, original assistant calls and the latest three verified successful exchanges in full. Each exchange includes a call batch and all its immediately following results.

The compacted result keeps its original tool role and call ID. A result over 512 bytes can become an excerpt containing up to 384 original bytes from its head and tail, a truncation notice and the exchange’s zero-based, end-exclusive source range in the working history for that request. The original arguments, signatures and row mapping survive. Shortening occurs only when the replacement is smaller.

Only successful outcomes observed by the current loop qualify. The existing transcript records result IDs and content but omits the execution success flag. On restart, the runtime sends previously recorded results in full. Pending, duplicate, incomplete, failed, malformed and prompt-mode exchanges stay raw. Structural hook rewrites also bypass this optimization because their source mapping is ambiguous.

## Files

- `crates/zeroclaw-runtime/src/agent/history_trim.rs` implements the request-only projection and its source, pairing, threshold and recent-tail checks. The pre-existing older-turn pairing changes remain in place.
- `crates/zeroclaw-runtime/src/agent/history_pruner.rs` exposes its existing result-ID reader within the crate.
- `crates/zeroclaw-runtime/src/agent/turn/mod.rs` records execution outcomes for the invocation and projects the prepared request after hook-based route selection. A mock provider captures normal, graceful-summary and resumed requests.
- `crates/zeroclaw-runtime/src/agent/turn/max_iter.rs` applies the same projection to the graceful final request and its whole-turn-trim rebuild.
- `crates/zeroclaw-runtime/AGENTS.md` was already modified when work began.

## Verification

```sh
cargo fmt -p zeroclaw-runtime
cargo fmt -p zeroclaw-runtime -- --check
git diff --check
CARGO_BUILD_JOBS=2 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p zeroclaw-runtime --lib --offline -- agent::history_trim:: agent::turn::max_iter:: agent::turn::tool_lifecycle_abandonment_tests:: agent::turn::sop_step_reassembly_tests::resumed_parent_request_keeps_its_tool_round_across_sop_step_prompts
```

Both formatting commands and the whitespace check exited 0. The focused test command exited 0 with 83 passed, 0 failed, 0 ignored and 6,129 filtered out. The active-turn fixture verified the trigger just above 70%, preserved the raw transcript and recent tail, and retained call IDs and source ranges. The provider fixture observed four full results on a fresh loop resumed from the original tool history, with no tool redispatch. Cargo reported an unused workspace dependency and two existing atomic-method deprecation warnings.

## Remaining limits

Large prompts, assistant call arguments, recent raw results and unresolved exchanges can still exceed the context window. The existing hard request guard remains authoritative. The focused checks use local mock providers. Live agent acceptance, full workspace CI, provider-specific token calibration and storage-backed process restart remain unverified.

## Independent validation — 2026-11-18

### Result: not accepted; no commit

The implementation does not meet the requested early-action criterion for the prior KAT growth pattern. `compact_active_tool_results` returns while there are three or fewer observed successful result IDs, and retains three recent exchanges. Therefore, at the stated 64K point after two large exchanges, it sends the request without compaction. At 82K after three exchanges, it still returns without compaction. The four-result unit fixture only demonstrates trimming once a fourth successful result has already arrived; it does not demonstrate protection at the earlier 64K request or avoid the subsequent 82K overflow. This is a source-level reproduction of the guard behavior; a live KAT reproduction was not run.

Per the task gate, Phase 2 was not started because Phase 1 failed this acceptance criterion. No local or hosted model was invoked, so there are no real KAT input-token counts, savings, or task-completion results. The smallest correction is to make eligibility depend on the context threshold and the number of older successful exchanges available, rather than requiring four successful IDs before considering any compaction, then add a regression for the two-result 64K point. This report does not implement that correction.

### Checks run

- `cargo fmt -p zeroclaw-runtime -- --check` — passed.
- `git diff --check` — passed.
- Focused runtime tests covering history trimming, graceful final requests, tool lifecycle, and resumed SOP turns — 83 passed, 0 failed.
- Full offline runtime library suite — 6,202 passed, 0 failed, 10 ignored.
- Existing warnings: unused workspace dependency `zeroclaw-dist`; deprecated atomic `fetch_update` calls in `rpc/dispatch.rs` and `rpc/upload.rs`.

The tests verify that the source history remains unchanged, only current-invocation successful native results are eligible, IDs and rows stay paired, ambiguous/failed/incomplete exchanges remain raw, resume does not redispatch completed calls, and the graceful final path applies the same projection. The passing test suite does not resolve the early-trigger failure above. Provider-specific token calibration, the real KAT model, and storage-backed process restart remain unverified.

### Worktree and tracking

At the end of independent validation, before the preservation action, no files had been committed. The implementation changes were in `crates/zeroclaw-runtime/src/agent/history_pruner.rs`, `history_trim.rs`, `turn/max_iter.rs`, and `turn/mod.rs`; the pre-existing `crates/zeroclaw-runtime/AGENTS.md` modification was preserved. `REPORT.md` was untracked. No push, merge, service change, or router change had occurred. The source branch at that point was `iaos69-compaction-mvp`, one commit behind `origin/master`.

The validation outcome was recorded as a separate comment on [IAOS #69](https://github.com/Me42019/IAOS/issues/69#issuecomment-6972153283). Keep this provider-facing tool-result optimization separate from IAOS #69's planned LFM2.5 semantic summarization, original-detail retrieval, durable source-linked summaries, automatic within-turn/across-turn compaction, and safe single-model router coordination. Its potential relevance to IAOS #70 tool-output work remains a separate planning note; neither task is complete.
