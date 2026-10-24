# ADR 0001: Kestrix as one installable local-first package

- Status: accepted
- Date: 2026-10-14
- Decision owner: Ruthvik Bandari

## Context

The CyberGuard Detection Repair plan (`docs/history/cyberguard-engineering-plan.md`, v2.0) proposed extending
the upstream `tanishka-bandari/cyberguard` Spring Boot and Next.js incident app with a Python analysis core.
A repository audit confirmed that baseline builds and passes its tests. On 14 October 2026 the project owner
changed direction:

- The upstream Java backend and Next.js frontend are not reused. The platform is rebuilt to production
  engineering standards instead of extending a student incident tracker.
- The product is a single Python package (`pip install kestrix`) with a CLI and a bundled local
  dashboard. It serves everyday users, students, practitioners and researchers.
- The package combines four modules: Sigma detection repair (the core of the plan), file and URL
  forensics (adapted from CyberSafeX Detection Suite), passive website exposure checks, and Bitcoin
  quantum-exposure scanning (adapted from BitShield, MIT Bitcoin Expo 2026, Team ACE).
- The earlier CTPPO attack-path code in this repository is retired. Git history keeps it.

## Decision

1. **Runtime:** a FastAPI application, served by `kestrix dashboard`, that binds to 127.0.0.1 by default.
   A prebuilt React SPA ships inside the wheel, so users need no Node toolchain.
2. **One shared core:** the CLI and the HTTP API call the same module functions. No business logic
   lives in either adapter.
3. **Detection repair semantics follow the plan unchanged:**
   - a bounded single-event Sigma subset
   - the pinned Elasticsearch 8.19.3 (digest-locked) as the only matching oracle
   - deterministic B0 repairs
   - development screening, then held-out validation with the plan's acceptance policy
   - explicit `unsupported`, `insufficient_evidence` and `abstained` outcomes

   ML stages B1 to M4 remain the research roadmap. They run on university HPC and are not part of this
   release.
4. **No accounts or multi-tenant server:** a single local user replaces the plan's Spring Boot identity,
   job and approval services. Job leasing, the outbox and analyst approval records are deferred until a
   shared deployment exists. Evidence is exported as content-addressed JSON (`--evidence-dir`).
5. **External services:** they are opt-in, per action, and always shown in the UI. Examples are
   mempool.space chain lookups and the user's own Anthropic API key for the Bitcoin guardian, stored only
   in a 0600 file or the environment. Outbound requests pass `core.netguard` (no private, loopback or
   metadata targets unless the user allows them) and connect to the validated IP.

## Consequences

- Plan items that depend on the multi-user backend are deferred, not dropped: FR07 (approval and
  export), FR10 (incident linkage), durable jobs and migrations.
- The plan's Claude setup (`.claude/`) is kept as the development workflow.
  Its CyberGuard wording is historical context for the detection-repair module.
- The plan's performance budgets now apply to a laptop-local run. Replay of each bundled case takes about
  0.2 s on the pinned engine, measured on an Apple Silicon laptop.
