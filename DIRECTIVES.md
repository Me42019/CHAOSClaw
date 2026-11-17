# CHAOSClaw — Development Directives

> **Build what we need. Preserve what works. Question everything else.**

CHAOSClaw is a maintained, local-first fork of [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw), built to serve real CHAOS household and agent workflows. It is **not** an attempt to recreate every feature of a general-purpose assistant framework.

## 1. Keep the foundation lean

- **Simple first; complex only when necessary.** Check whether an existing setting, component, upstream feature, or proven library already solves the problem.
- Add features because a demonstrated workflow needs them, not because another platform has them.
- Every new service, dependency, layer, and abstraction must justify its maintenance cost.
- Favor clear ownership boundaries, small modules, readable code, and narrow interfaces.

## 2. Rust-first, not Rust-at-any-cost

- Prefer Rust for the agent/runtime backend, tool execution, observability, memory, context management, and other long-lived infrastructure.
- Reuse well-maintained Rust crates and existing ZeroClaw machinery before creating new frameworks.
- Keep the practical Tauri/web frontend where it fits. Do not rewrite functioning components solely for language purity.
- Avoid needless cross-language bridges and extra always-on processes.

## 3. Preserve ZeroClaw's strengths

- Keep tool visibility and execution understandable to small local models.
- Preserve isolation, truthful tool receipts, explicit delegation, and separation of the desktop, Gateway, and inference runtime.
- Maintain upstream compatibility when practical; evaluate upstream fixes before carrying permanent fork-only patches.
- Don't trade a working foundation for a large speculative redesign.

## 4. Make failures observable and recoverable

- Prefer built-in diagnostics first; add focused instrumentation only for a demonstrated evidence gap.
- Capture enough to distinguish model behavior, tool/schema issues, permissions, context failure, routing, and UI faults.
- Keep logs bounded, locally controlled, and privacy-conscious; do not persist household prompts, credentials, or tool secrets by default.
- Never count an agent's claim of success as proof. Check outputs, test results, traces, and recovery behavior.

## 5. Develop with clear authority and evidence

- Jeremy decides architecture, consequential changes, production adoption, and Git commits/pushes.
- Give local agents scoped, precise work with authoritative files, permitted edits, tests, and deliverables. Use stronger models when complexity genuinely warrants them.
- Independent review must distinguish planned work, claimed work, and independently verified results.
- Preserve dirty worktrees, ongoing sessions, existing fixes, and evidence. Work in separate branches/worktrees when tasks can overlap.
- Test before accepting repairs. Prefer the smallest maintainable fix that addresses the verified cause.

## 6. Build for actual use

- Prioritize reliable context handling, memory, useful tools, understandable delegation, and a comfortable everyday desktop experience.
- Test agents on real, bounded tasks, one local model at a time when the inference router requires it.
- Keep the existing installation operational while developing and require explicit approval for disruptive service changes or household migration.
- When a simple solution works, stop adding machinery.

---

**Guiding question:** *Does this make CHAOSClaw more useful, understandable, and maintainable for the people actually using it?* If not, it probably doesn't belong.
