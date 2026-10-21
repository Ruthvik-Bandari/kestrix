# Kestrix redesign handoff

Prepared 21 October 2026. **Design proposal, not an implemented application redesign.**

The problem is hierarchy and repetition: the workbench repeats its navigation as nine equal tiles; the public page repeats six oversized comparison chapters; tool instructions push the task below the first screen. The proposed direction makes the product feel more professional through clearer composition, useful evidence, and a consistent interaction system.

## Open this first

Open [the interactive visual proposal](visual/index.html) in a browser. It has four views: Website, Workspace, Email report, and Design system. Try the theme and runtime-mode selectors, tool navigation, finding filters, and evidence disclosures. The prototype uses local fonts and synthetic examples; it does not analyze inputs or connect to your accounts.

During this review it is also served at [localhost:8799/visual/](http://127.0.0.1:8799/visual/). If the preview server has stopped, open `visual/index.html` directly, or run this from the repository root:

```sh
python3 -m http.server 8799 --bind 127.0.0.1 --directory docs/design/2026-10-21-redesign
```

Saved views: [website](evidence/proposed-hero.png), [workspace](evidence/proposed-workspace-desktop.png), [email report](evidence/proposed-report-desktop.png), [dark report](evidence/proposed-report-dark.png), and [mobile website](evidence/proposed-website-mobile.png).

Then read:

1. [Audit and implementation plan](PLAN.md): current problems, content architecture, source map, phased work and acceptance criteria.
2. [Design specification](DESIGN.md): visual tokens, layout rules, component behavior, responsive treatment, and content rules.
3. [Claude prompts](CLAUDE-PROMPTS.md): copy-ready lead, implementation, and review instructions for the Opus/Sonnet pairing you requested.
4. [Verification notes](VERIFICATION.md): what was actually reviewed and tested, and the limits of this proposal.

## How to give this to Claude

Give the entire `docs/design/2026-10-21-redesign/` folder to the implementation session, including `visual/` and its assets. Start with the **Opus lead prompt** in `CLAUDE-PROMPTS.md`. Work through one numbered phase at a time, passing each approved slice to Sonnet, then having Opus review the actual browser result and diff.

The model names are role labels requested by the owner, not verified API model identifiers. Use the corresponding models available in your Claude environment. This plan does not depend on a particular model version.

## What this proposal chooses

- Cover the public website and the workbench together; no narrower preference was supplied during the review.
- Use a graphite, ivory, and green visual system with existing IBM Plex fonts. This is a proposed direction, not a recorded user-approved brand change.
- Lead with a useful report, then explain capabilities. Keep specialist tools visible with accurate availability labels.
- Reuse the existing React, routing, query, report, authentication, and API foundations.
- Preserve the distinction between local and hosted processing, and the current 30-day report retention behavior.

The preview is a visual and interaction reference. Production uses existing React components, typed contracts, authenticated routes and real API states. Mock fixtures and preview controls must not become production behavior.

## Deliverable boundary

Application source, backend, dependency manifests, root `CLAUDE.md`, and repository workflow were not changed by this design task. This folder is the handoff. There was no deployment or production migration.
