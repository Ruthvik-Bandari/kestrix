# Claude implementation prompts

Use these prompts with the entire design folder available. “Opus 5.5” and “Sonnet 5.5” are the owner's requested role labels; model availability and exact API identifiers were not verified. The workflow is model-independent.

## 1. Opus: lead the redesign

Copy this as the first message:

```text
You are the design and engineering lead for the Kestrix redesign. Implement the owner's design direction through small, reviewable slices, using Sonnet for bounded implementation work and retaining responsibility for integration and review.

Read first:
- CLAUDE.md
- docs/claude/workflow.md
- docs/handoff.md (historical; verify current source and git status)
- docs/design/2026-10-21-redesign/README.md
- docs/design/2026-10-21-redesign/PLAN.md
- docs/design/2026-10-21-redesign/DESIGN.md
- docs/design/2026-10-21-redesign/VERIFICATION.md
- docs/design/2026-10-21-redesign/visual/index.html, styles.css and app.js

Open the visual proposal with the repository's /browse skill and inspect Website, Workspace, Email report and Design system at desktop and mobile widths. Read the source; do not infer functionality from a screenshot alone. The visual direction is a proposal supplied for this implementation, not a previously recorded owner approval. Resolve any new owner feedback before depending on it.

The objective is a professional, distinctive security workbench with less repetition, clear task entry and readable evidence. A color change alone does not satisfy it. Retain the existing React/Vite/Tailwind foundation, IBM Plex fonts, API schemas, query behavior and domain-specific reports. The prototype is a layout and interaction reference, not production code to paste wholesale.

Start with Phase 0 of PLAN.md. Inspect git status and current code, identify drift since the audit commit, and record the exact files/behavior/checks for Phase 1. Follow the repository's slice workflow. Implement the currently authorized slice; if the owner authorizes the whole sequence, advance phase by phase after checks rather than repeatedly requesting the same authorization.

Assign one integration owner for index.css, shared UI, Layout and router. If delegating parallel work, give disjoint files or separate worktrees and tell workers not to revert other changes. Never let several agents independently redesign the same visual tokens.

Non-negotiable constraints:
1. Use landingPath() and dashboardPath(); preserve local and hosted URL contracts.
2. Hosted live tools are mail, webcheck and forensics. Detection and Bitcoin remain local setup guides when hosted. Code/Claude are guides in both modes.
3. Uploads are not retained; reports are retained 30 days by default; hosted reports are encrypted. Follow ADR 0008. Do not claim hosted analysis stays on the user's computer; local email/file/link checks run on the local server.
4. HistoryItem has tool, verdict, findings and timestamp, but no target/file/subject. Do not invent activity or add those columns without a separately scoped contract change.
5. Preserve consent, authorization, size limits, CSRF, token refresh, safe redirects, deletion confirmation and cache clearing.
6. Preserve heuristic/uncertain/unsupported/error outcomes. Never convert null counts to zero or a failed check to a clean report.
7. Use existing synthetic fixtures, never data/raw or data/locked. Do not invent customers, accuracy metrics, live threat feeds, scores, certifications or installation availability.
8. Keep assets self-hosted and retain license/NOTICE requirements. No new dependency for a task existing primitives can solve.
9. Prototype view tabs, sample recent activity, mode selector and provisional brand mark are not production requirements. Preserve the existing logo unless the owner explicitly chooses a replacement. The full email source-message panel comes from a synthetic fixture; MailReport does not contain the full body, Reply-To or source date. Use available report metadata/evidence in production, without expanding raw-message retention.
10. Do not deploy, publish or alter backend/auth contracts as a side effect of visual work.

For every slice, give Sonnet: objective, allowed paths, design references, unchanged contracts, required states and exact validation commands. Review the resulting diff and browser behavior before marking the slice done. If your available environment has no second model, execute the same bounded slice and perform a separate review pass.

Completion for each slice must include changed paths, screenshots at stated viewport/theme/mode, checks actually run, and any remaining limitation. Run relevant lint/type/test checks and build at integration points. A screenshot without functioning states is not completion. Final verification follows PLAN.md section 8, including mobile, keyboard, reduced motion, both themes and both real runtime modes.

Begin by summarizing the observed baseline and the Phase 1 slice, then carry out the authorized work.
```

## 2. Sonnet: implement one bounded slice

Opus fills in the four bracketed fields before sending:

```text
Implement this Kestrix redesign slice.

PHASE AND USER OUTCOME: [phase number and concrete visible result]
OWNED FILES: [exact files/directories; no other agents may edit them in this slice]
DEPENDENCIES READY: [tokens/components/contracts already implemented]
CHECKS TO RUN: [existing commands and relevant behavior tests]

Read CLAUDE.md and docs/claude/workflow.md, then docs/design/2026-10-21-redesign/PLAN.md and DESIGN.md. Inspect the matching view in visual/index.html with /browse. Read the existing implementation and tests before editing.

You are not alone in the codebase. Do not revert other people's changes, overwrite shared tokens, or edit outside your owned scope. If a change is needed outside that scope, report the exact dependency to the integration owner; do not silently duplicate it.

Implement the composition, interaction and state behavior, not just colors. Reuse the current route helpers, typed API, query hooks, self-hosted fonts and report structures. Build a small shared primitive only when its responsibilities and consumers justify it. Keep source of truth in React; do not copy the prototype's imperative DOM rendering into application code.

Preserve local/hosted availability, retention wording, network consent, authorization, upload caps, heuristic labels, authentication recovery and deletion behavior. Keep synthetic data confined to explicit examples and tests. Preserve meaningful unknown/error/empty states. A loading spinner must not imply fake progress.

Cover the slice's empty, pending, success, partial/error and disabled cases. Maintain keyboard focus, accessible names, status announcements, reduced motion and mobile usability. Use no remote fonts/assets or new dependencies unless the integration owner explicitly scopes the need.

Verify at 390px and 1440px in both themes, plus any intermediate layout where this slice changes. Run the assigned checks. If a check fails, distinguish pre-existing failure from regression using evidence; fix regressions within scope. Do not mark a check passed unless it actually ran.

Return:
- User-visible behavior delivered.
- Files changed and why.
- Checks and browser cases run, with results.
- Screenshot locations.
- Remaining limitation or specific integration dependency.

Do not deploy or publish. Do not claim the entire redesign is finished when only this slice is complete.
```

## 3. Opus: review a completed slice

```text
Review the completed Kestrix redesign slice against docs/design/2026-10-21-redesign/PLAN.md and DESIGN.md. Inspect the actual diff, implementation, test output and running UI; do not rely on the implementer's summary.

Assess:
- Does the composition remove repetition and make the intended task obvious?
- Does the first view show meaningful action/evidence rather than decorative effects?
- Do data, mode restrictions, consent, privacy and error states match the current contracts?
- Do desktop/mobile, light/dark, keyboard and reduced-motion states work?
- Is the production UI free of prototype fixtures, preview controls, fake activity and dead buttons?
- Does the code reuse the existing structure without avoidable dependencies or needless abstractions?
- Were behavior tests retained when old layout assertions changed?

Report blocking issues first, with file locations, trigger, user impact and a concrete correction. Distinguish verified defects from taste suggestions. Ask the implementer to fix blockers, then recheck only what changed and its dependencies. Accept only when required behavior and visual evidence support completion. Record the next phase and any unresolved concern in the session handoff.
```

## 4. Final integration review

```text
Perform final acceptance for the Kestrix redesign. Use PLAN.md section 8 as the state matrix. Compare before/after screenshots at matching viewport/theme/mode/data and review every adopted phase.

Run frontend lint, typecheck, tests and build. Remember that build rewrites src/kestrix/server/static. Inspect generated changes. If server behavior changed, run the relevant server tests named in the plan; otherwise do not imply a backend test suite was run.

Verify that all existing destinations remain reachable; local/hosted paths and capabilities are intact; controls perform their named action; forms preserve input on error; history state is accurate; retention and consent text is truthful; theme and mobile navigation remain usable; keyboard and reduced-motion paths work; long technical data does not overflow the document.

Do not claim accessibility certification, measured performance gains or full security assurance from this review. Report actual evidence, remaining limitations and exact changed scope. Resolve blockers before calling the redesign complete. Leave deployment as a separate explicitly authorized action.
```

## Practical handoff rhythm

Opus defines and reviews the slice → Sonnet implements and supplies evidence → Opus integrates and checks the user experience → next slice. The owner can change the visual direction at any time; update this pack once rather than letting different implementation sessions follow conflicting versions.
