# IAOS #69 context growth between Lossless checkpoints

The exact **+5,960** is `39,138 − 33,178` in the 16-record Norman run on
the reviewed `bc4fd17c2c7ebec5d92abb73e4ce85096a33b9b5` candidate. The
interval contains **one completed file read**, record 06. The two endpoints
are calibrated runtime estimates, on opposite sides of the next compaction.
The two successful Norman calls around that boundary differ by **150
provider-reported input tokens** after the second compaction was applied.

| Run and boundary | Start after compaction | Next checkpoint before / after | Net estimated growth before next compaction | Completed reads in interval | Adjacent Norman provider-reported inputs |
| --- | ---: | ---: | ---: | --- | ---: |
| 16 records, `b68fc307…` → `76f50465…` | 33,178 | 39,138 / 33,366 | **5,960** | Record 06 | 33,178 → 33,328 (+150) |
| 16 records, `76f50465…` → `56c89655…` | 33,366 | 39,281 / 33,676 | 5,915 | Record 07 | 33,328 → 33,565 (+237) |
| 12 records, `e8a518a8…` → `e446ca0f…` | 33,175 | 39,258 / 33,643 | 6,083 | Record 06 | 33,280 → 33,580 (+300) |
| 12 records, `e446ca0f…` → rejected LFM summary | 33,643 | 39,548 / no projection | 5,905 | Record 07 | 33,580 → 40,628 (+7,048) |

The first interval spans Nov 19, 2026, 8:33:48.258–8:35:00.004 p.m.
CST (Nov 20 02:33:48.258–02:35:00.004 UTC in `compactions.tsv`).
Norman request 6 ran on the first projection and produced record 06. The
next compaction replaced the oldest remaining raw round (record 02) with
a summary before Norman request 7. The estimate at 39,138 was internal to
compaction preparation. The router never evaluated that unprojected
population. The reports at 33,178 and 33,328 apply to the two projected
requests. Timestamp proximity and the logged request order pair them to
the two successful completions in the cost ledger and router timings.

| Component | Evidence in the +5,960 interval | Accounting |
| --- | --- | --- |
| New file result | One full `file_read` of record 06, 11,940 file bytes | 12,419 bytes of numbered text, 12,614 bytes in the serialized canonical result carrier, including pairing ID and framing. Plain-text estimator share is about 3,109 uncalibrated tokens including per-row framing. |
| Assistant and tool call | One native assistant carrier, 211 serialized bytes | Visible assistant content was empty. The stored reasoning was 53 UTF-8 bytes and the compact tool-call array was 105 bytes. Carrier share is about 57 uncalibrated tokens including per-row framing. |
| System and tool schemas | 16,975 system characters and two native schemas | Stable recorded system and schema fingerprints in requests 5, 6 and 7. No delta indicated. Absolute schema tokens and rendered chat-template overhead were absent. |
| Checkpoint data | First note 50 bytes, second note 69 bytes | Source reconstruction yields 431 and 450 bytes respectively including labels, trust language, source ID and JSON escaping. The first note was retained in the user anchor across the interval. The second was inserted after the 39,138 estimate, replacing a 12,419-byte result and its assistant carrier. |
| Synthetic messages | Projection kept ten message rows before and after the subsequent dispatched compaction | The historical source appends summary text to the existing user row. It adds no synthetic call/result pair. The local analysis observed no additional synthetic rows. |
| Repeated or retained history | No duplicate reads, invalid pairs, or duplicated canonical reads in the audit | At both dispatched checkpoints the latest four raw rounds are protected. The gap between compactions temporarily adds a fifth raw round. Stored rows and matching counts give no evidence of anomalous retention. Exact provider-facing row inventories before the second compaction were unavailable. |
| Calibration | Previous same-route provider usage divided by its prior raw estimate when the ratio exceeds one | The approximately 3,166 raw estimator units for the new round would yield +5,960 at a factor of about 1.88. The logs do not record the exact raw denominator, scale or per-bucket residual. |
| Route and budget | Same Norman generation route and limits throughout this boundary | 65,536 model window, 32,000 soft prompt budget, 24,000 compaction trigger and 4,096 reply reserve in the Lossless implementation. LFM was a separate 16,384-token summary route. Its second prefill processed 6,043 tokens, separately from Norman. |
| Router work | Reported prompt input corroborated by the cold router prefill after each swap | Norman reloaded in 1.818 s and 1.807 s. Cold prompt processing was 59.121 s and 59.562 s for the two completions. Earlier warm requests processed about 6,960–6,990 fresh tokens per new large read, plus the cached prefix. |

The ordinary growth is consistent with one intentionally large synthetic
read and its assistant/tool-call envelope. In the shorter run where
compaction was rejected, an equivalent single round produced a directly
observed 7,048-token input increase without a projection. There is no
evidence here for a harness defect. The exact uncalibrated request
populations at both estimate endpoints, their per-role byte/token
breakdowns, the preceding calibration denominator, the server's rendered
chat template tokens by component, and per-row request fingerprints were
not retained. Those are the missing measurements for exact attribution
or excluding provider-adapter replay duplication. No inference was run
to reconstruct them.

## Evidence and method

Use the owner-supplied `acceptance-bc4fd17.jLzPV8/` evidence root.

- `ACCEPTANCE-REPORT.md` establishes the tested build, scope and limits.
- `norman-acceptance/compactions.tsv` and both runs' `audit.log` and
  `candidate-trace.jsonl` supply checkpoint boundaries and request/round
  ordering. The safe trace has system/schema counts and hashes but omits
  request content.
- Each run's `config/data/state/costs.jsonl` supplies actual Norman usage.
  Each run's `router-timings.log` supplies prefill and model load timings.
  Warm prompt evaluation tokens measure evaluated work and can exclude the
  cached prefix. The cost ledger captures the total logical input.
- `recovered-checkpoints/{norman-acceptance,norman-completion}.sqlite`
  was read in immutable mode for canonical tool payload byte counts,
  assistant envelopes and saved summary text. Fixtures were measured on disk.
  Summary lengths were rebuilt with the exact reviewed projection framing.
  The checkpoint database is evidence of source history, not a wire capture.
