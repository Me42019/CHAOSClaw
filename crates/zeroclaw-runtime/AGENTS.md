# CHAOSClaw Runtime — Coding Instructions

**Scope:** `crates/zeroclaw-runtime/` in the CHAOSClaw fork.

Follow the repository-root `AGENTS.md` and `DIRECTIVES.md`. This file adds only runtime-specific guidance. It replaces the upstream holding-crate exception ledger **for CHAOSClaw development**, not for contributions submitted upstream.

## Purpose and approach

This crate contains runtime systems that may be extracted into smaller crates over time. **Fix or extend the existing code when an approved task requires it.** Do not block useful work merely because a subsystem has not yet been extracted. Prefer an existing component or setting; extract or redesign only when the task and evidence justify it.

## Authority

- **Jeremy approves** architecture, consequential scope changes, production changes, and Git commits/pushes.
- Within an approved, scoped task, agents may edit development source and tests in the assigned worktree and run appropriate checks without seeking approval for every ordinary edit.
- Preserve dirty worktrees, active sessions, and evidence. Do not reset, clean, commit, push, or change live services, router settings, or deployed configuration without authorization.
- Do not silently weaken security, tool permissions, approval rules, privacy, or recovery guarantees.

## Working method

1. Read the task contract and relevant root guidance; inspect **only the owning code, nearby callers, tests, and documentation needed**. Search large references for relevant sections instead of loading them wholesale.
2. Make the smallest coherent change that solves the verified problem. Reuse canonical state and existing interfaces; avoid duplicate configuration, speculative abstractions, and unrelated cleanup.
3. Preserve typed tool calls/results, execution provenance, session history, and error handling when changing the agent loop. Add focused regression tests for behavior changes.
4. Report what changed, tests actually run and their results, remaining risks, and any decision needed. Use the task's `REPORT.md` handoff location when one is provided.

## Upstream reference

ZeroClaw's historical exception ledger and ADR-016 remain useful **upstream references**, not an automatic Core Team approval gate for fork-only changes. Follow upstream governance separately if preparing a contribution to ZeroClaw itself.

**Principle:** Build what CHAOSClaw needs, keep what works, and make changes easy to verify.
