# Documentation index

## User guides

- [api.md](api.md) HTTP API reference
- [hosted.md](hosted.md) hosted mode
- [deploy.md](deploy.md) deployment
- [release.md](release.md) release process
- [claude-plugin.md](claude-plugin.md), [claude-skill.md](claude-skill.md), [plugin-submission.md](plugin-submission.md) Claude Code plugin and skill
- [demo/README.md](demo/README.md) demo project

## Modules

[detect](modules/detect.md), [forensics](modules/forensics.md), [mail](modules/mail.md), [webcheck](modules/webcheck.md),
[bitcoin](modules/bitcoin.md), [code](modules/code.md), [code rule provenance](modules/code-rules-provenance.md)

## Decisions and design

- [adr/](adr/) architecture decision records (start with [0001](adr/0001-platform-direction.md))
- [design-system.md](design-system.md) the dashboard design system
- [security-model.md](security-model.md), [model-card.md](model-card.md), [provenance.md](provenance.md)

## Evidence

- [benchmarks/](benchmarks/) measured results, for example [detect](benchmarks/detect.md), [CVEfixes](benchmarks/cvefixes.md), [plugin A/B](benchmarks/plugin-ab.md)
- [research/](research/) plans, benchmark write-ups and the [language roadmap](research/language-roadmap.md); the [detection-repair runbook](research/detect-runbook.md) and [cluster jobs](research/hpc.md)
- [`research/results/`](../research/results/) published aggregates; [dataset card](../research/results/dataset-card.md) datasets and licenses

## Research code

The published wheels hold only `kestrix` (`src/kestrix`) and `kestrix-scan` (`packages/kestrix-scan`). The research
packages `kestrixbench`, `kestrixvul`, `kestrixmailbench`, `kestrixcodebench`, `kestrixlinkfilebench` and
`kestrixscanbench` stay under `src/` so that ruff, strict mypy and pytest cover them like the shipped code, but the
build backend packages only `kestrix`. Their data and jobs live in `research/`: Slurm jobs per track in
`research/hpc/`, aggregates in `research/results/`, the scanner benchmark cases in `research/scanbench/` and
measurement tools in `research/scripts/`.

## Legal and history

- [legal/privacy-draft.md](legal/privacy-draft.md), [legal/terms-draft.md](legal/terms-draft.md)
- [history/cyberguard-engineering-plan.md](history/cyberguard-engineering-plan.md) the original detection-repair plan (historical)
- [.claude/handoff.md](../.claude/handoff.md) session state
