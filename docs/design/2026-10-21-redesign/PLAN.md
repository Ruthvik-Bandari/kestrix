# Kestrix: redesign plan

## 1. Outcome

Make Kestrix feel like precise, trustworthy security software. A new visitor should understand its purpose from the first screen. A returning user should reach an input immediately. A report should answer three questions in order: **What did the check find? What is the evidence? What should I do next?**

Professional quality comes from useful hierarchy, credible content, thoughtful states and consistent execution. Adding more visual effects or more sections will not solve the current problem.

Scope: public landing, application shell, Home, tool inputs and reports, history, guides, auth and supporting pages. No new analysis engine, monitoring system, billing, backend architecture or model integration is required.

## 2. Evidence from the current site

Reviewed the running local site at `http://127.0.0.1:8765` and source at commit `1ffdf2f0f9658efa42faa67089fe4130c468ff74`. Live browser inspection covered `/welcome`, `/`, and `/mail`. Hosted behavior and the other modules were reviewed in source; this is not a claim of a complete live hosted test.

| Finding | Evidence in current code/site | Required change |
|---|---|---|
| Home repeats navigation | `features/home/HomePage.tsx` presents nine equally prominent tiles, duplicating `app/Layout.tsx` navigation | Replace tile wall with compact tasks, recent reports, and a quieter specialist-tools area |
| Six chapters repeat the same experience | `features/landing/LandingPage.tsx` maps `chapters` into `Chapter`, `Compare`, and `RealOutput`; the local page was 9,278 CSS px tall at 1,280px wide | One featured report; compact tool discovery; a single process explanation and trust section |
| Hero explains the page gimmick | “Six everyday moments…Drag the beam” describes the comparison interaction before the tool | State the product's purpose and show an already-visible result |
| Useful output starts hidden | `features/landing/Compare.tsx` defaults to `initial = 0`, the “without” scene | Put the Kestrix result on screen immediately; make comparisons optional |
| Repeated explanation precedes action | `components/HowItWorks.tsx` defaults open; `/mail` input appears well below the initial viewport | Put input first with a one-line purpose; use optional help and contextual limitations |
| Decoration has no hierarchy | `index.css` applies glass, iridescent borders, rainbow titles and animation to routine panels | Solid work surfaces; one brand accent; status colors reserved for findings |
| Conversion actions compete | Hosted hero includes auth form, story action and dashboard action | One primary action and one sample action; retain the existing dedicated sign-in page |
| Navigation labels conflate capability | Browser tools, local-only analysis and CLI setup guides share visual priority | Group by task and show “Run locally” / “Setup guide” where appropriate |
| Active chapter tracking is broken | `useActiveChapter` stores `chapter-invoice` but looks up `invoice` | Remove the mechanism with the chapter architecture; normalize IDs if retained |
| Public logo destination is inconsistent | Landing brand links to dashboard; `PublicShell` brand links to landing | Public logo goes to public home; explicit action enters workbench |
| Mobile public navigation disappears | Landing chapter navigation uses `hidden lg:block` with no equivalent menu | Provide accessible mobile navigation with the same useful destinations |
| Some claims need reconciliation | “Contained” implies mitigation; install section says release pending beside `pip install`; hosted users encounter local-centric privacy messaging | Describe verified analysis behavior, current install availability and mode-specific data handling |

Existing strengths to retain: genuine outputs on labeled synthetic fixtures, readable IBM Plex fonts, explicit verdicts and reason codes, typed APIs, mode-aware routes, keyboard controls, reduced-motion support and behavior tests.

## 3. Design direction

**Working name: Evidence, clearly.** A dark editorial opening introduces the product; a quiet workbench lets users inspect evidence. The distinguishing visual is a compact, readable investigation, not a decorative globe.

Use graphite and warm off-white surfaces, forest green actions, restrained lime accents in the public hero, and semantic red/amber/green for results. Retain self-hosted IBM Plex Sans and Mono. See `DESIGN.md` for implementation values.

Two deliberate design choices:

- A large asymmetric public composition creates a stronger first impression. Its cost is tighter editorial discipline: short copy and one dominant example, rather than giving every tool an entire chapter.
- The application is visually quieter than the marketing hero. Its benefit is better evidence reading; its cost is fewer decorative flourishes. Shared type, navigation, spacing, buttons and colors keep both surfaces recognizably Kestrix.

This direction is a proposal. Do not record it as approved user feedback, and do not infer that the owner requested a full logo rebrand. Preserve the existing brand asset in implementation unless the owner chooses the provisional mark shown in the preview.

## 4. Public website architecture

| Order | Section | Job and content | Exit/action |
|---|---|---|---|
| 1 | Header | Brand, Product, Example, Privacy, Docs; clear workbench action | Public logo returns to `landingPath()`; workbench uses `dashboardPath()` |
| 2 | Hero | “See the risk. Understand the evidence.” Supporting copy names email, files, links and websites. Show a report from the existing synthetic email sample | Primary “Open workbench”; secondary “Explore an example” |
| 3 | Tool explorer | Compact task rows, input type and availability. Email; Website; File & link. Separate specialist area for Detection, Code/Claude, Bitcoin | Direct mode-aware task links |
| 4 | One explanation | Provide input → inspect evidence → decide next step. Each step has distinct content and a compact illustration or report detail | View the selected example or relevant guide |
| 5 | Trust | Local versus browser processing, upload/report handling, analytical limits, source availability | Privacy and documentation links |
| 6 | Closing action/footer | One invitation to start; Docs, GitHub, license, privacy, terms and attribution | Enter workbench |

Constraints:

- A 1440×900 desktop first view shows the proposition, primary action, and meaningful report evidence.
- On 390px mobile, the proposition and primary action precede the report. No instruction to drag a comparison slider is required to understand the product.
- Target about 3–4 desktop viewport heights for the complete landing page, allowing natural variation for text zoom and device size. Do not force height to meet an arbitrary screenshot length.
- Do not add a testimonial wall, customer logos, pricing, uptime, certifications or accuracy metrics without real evidence.
- Preserve source provenance for sample outputs. “11 findings / 5 high” is the bundled email example, not a product performance statistic.
- Keep detailed examples in a selectable library or docs if useful. Do not replace six repeated chapters with six repeated feature cards of the same size.
- The copyable installation command must match an actually available distribution. Check repository release/install instructions at implementation time; do not silently convert a pending PyPI release into a published claim.

## 5. Workbench architecture

### Navigation and Home

Desktop rail: about 224px, with Overview; Checks (Email, Website, File & link); Advanced (Detection repair, Bitcoin); Developer tools (Code scanner, Claude integration); Workspace (Recent results, Settings); quieter Docs/help.

Home contains:

1. Short heading: “What would you like to check?” with a mode indicator.
2. Three compact primary task rows showing the input each tool accepts. File/link remains a tool group with two distinct actions.
3. Recent results sourced from `useHistory()`: Tool, Result, Findings, Time. Use `HistoryItem.id` for navigation. The existing summary API has **no filename, subject or target URL**; do not invent those columns.
4. A subdued local/developer area with appropriate live-tool or setup-guide labels.

Home does not need an overall security score, “threats blocked,” trend charts or a live event feed. The product has no data contract for them.

History states: loading placeholder; saved entries; first-use empty message with task action; disabled history explanation with settings link; fetch failure with retry; deletion reflected across Home and History queries. Empty history is not “zero threats.”

### Inputs and reports

Standard structure: title and one-line purpose → primary input and required consent → optional advanced fields → run action → result. At wide widths use input/report columns where helpful; stack on small screens. A report-only history page should use the available width rather than retaining an empty input column.

`HowItWorks` becomes optional contextual help, collapsed by default for new users. Preserve a user's explicit stored preference. Keep the short processing/retention notice and required authorization beside the action; do not hide material consent in a disclosure.

Report order:

1. Verdict, outcome or grade with an icon and text label.
2. A plain-language summary and domain-specific next step.
3. Findings ordered by severity, with count and meaningful filter controls.
4. Evidence expanded on demand; source context when the report contract provides it.
5. Export/raw data/provenance and limitations.

Display severity separately from brand color. Keep actual reason codes and technical evidence available without making them the first thing every user reads. Do not imply that suggestions have already been applied.

**Preview boundary:** the email preview's full source-message panel comes from the synthetic marketing fixture, not `MailReport`. The current report contract includes subject, sender address, hash, findings and counts, but no full message body, Reply-To field or source date. Production and history should show available metadata and evidence in that panel. Do not add raw-message retention or a new parser merely to reproduce the fixture illustration. Curated next-step wording must be implemented explicitly as reviewed presentation copy; it is not an existing API field.

### Domain-specific treatment

| Tool | Main input | Distinctive result | Essential states/constraints |
|---|---|---|---|
| Email | `.eml` chooser; optional protected domains and trusted authserv-id | Verdict, sender/link/attachment evidence, per-finding details | 25 MiB local / 10 MiB hosted; no link visits or attachment execution; clean is not a guarantee |
| Website | URL + explicit authorization; optional settings | Grade, failed checks, evidence and fix recommendations | Pending, failed connection, partial analysis; public targets only hosted; local private-target option stays local |
| File | File chooser | Type mismatch, hashes, entropy, metadata and findings | 50 MiB local / 10 MiB hosted; do not execute files; preserve charts and format-specific details |
| Link | URL as text | Domain decomposition and suspicious signals | No fetch implied; empty/invalid input; results are heuristic |
| Detection repair | Case selection or rule/mapping/event inputs | Diagnosis, patch diff, held-out replay counts and reason codes | All explicit outcomes; unavailable engine; null counts are not zero; hosted shows local guide |
| Bitcoin | Address list; optional chain lookup | Address type, key exposure, uncertainty and migration explanation | Preserve consent, unknown cases and read-only behavior; hosted shows local guide |
| Code / Claude | Setup instructions and copyable commands | Clear install/configure/verify steps | Guides, not invented browser scanning or live integration status |

### Supporting pages

- History: compact accessible list/table, detail view, truthful disabled/expired/missing states, existing deletion confirmations.
- Settings: sections grouped by outcome; retention, accounts, local options and destructive controls remain explicit.
- Sign-in: use `AuthCard`, provider availability and safe return handling; remove the duplicate form from the marketing hero if adopted.
- Guides: short setup checklist, prerequisite explanation, copyable command, verification step, docs link. Avoid a second marketing page inside the app.
- Docs/legal: shared type and spacing; long-form readable width; preserve factual and legal content.
- Public docs are a routing improvement, not a prerequisite for the visual redesign. If moved outside hosted auth, keep `/app/docs` compatibility and test precedence carefully: local `/docs` already exists. This is a separate phase, not an incidental route rewrite.

## 6. Contracts that must survive

1. `landingPath()` and `dashboardPath()` remain the route source of truth. Local: `/welcome` + `/`. Hosted: `/` + `/app`.
2. Hosted live analysis is mail, webcheck and forensics only. Detection and Bitcoin render local setup guides. Code and Claude routes are guides in both modes.
3. Raw uploads are not retained; reports are retained for 30 days by default. Hosted reports are encrypted. Turning history off deletes existing reports. Follow ADR 0008 over older ADR 0004 wording.
4. Local email/file/link analysis stays on the local server; hosted processing happens on the server. Website checks connect to the target. Optional chain lookup and AI use remain explicit network actions.
5. Keep CSRF, token refresh, provider discovery, safe return paths, sign-out cache clearing and account/report deletion protections intact.
6. No business logic or security rules move into presentation components. Keep existing API/report schemas; use adapters only for view formatting.
7. Heuristic scores are not probabilities. Preserve insufficient evidence, unsupported, abstained, unavailable and partial states.
8. Keep assets self-hosted for the existing CSP. Preserve attribution and licensing. Do not add remote font scripts, analytics or a new chart library to solve a styling issue.
9. Never load `data/raw/` or `data/locked/` for screenshots or tests. Use existing synthetic samples.
10. The preview's view tabs, mode switch and fixture data are review controls. Production mode is determined at startup, never selected by a user-facing toggle.

## 7. Implementation sequence and ownership

The existing workflow calls for one reviewable slice per session. Treat these as ordered tickets; split large phases further. Opus owns architectural decisions and review; Sonnet implements bounded slices. One integration owner owns `index.css`, `app/Layout.tsx`, `app/router.tsx`, and shared UI. Do not let two agents edit these simultaneously.

| Phase | Deliverable and source ownership | Dependencies | Exit evidence |
|---|---|---|---|
| 0 | Opus reads this pack + `CLAUDE.md`, current handoff, workflow and current git diff; records baseline screenshots and capability map | None | Exact approved slice, allowed paths, unchanged contracts and checks |
| 1 | Tokens, typography, buttons, fields, panels, status treatment in `frontend/src/index.css`, `components/ui.tsx`, `tone.ts`; keep existing token names where possible | 0 | Existing pages remain legible in both themes; primary/hover/focus/disabled/status specimens |
| 2 | Public landing composition in `features/landing/LandingPage.tsx`, `content.ts`, `parts.tsx`; scope decoration; remove obsolete chapter machinery after checking callers | 1 | Desktop/mobile screenshots; samples visible; no misleading claims; public/hosted CTA paths correct |
| 3 | Shell and action-focused Home in `app/Layout.tsx`, `app/tools.ts`, `features/home/HomePage.tsx`; reuse `useHistory` and existing query keys | 1 | Empty/saved/disabled/error history; accessible mobile navigation; all existing destinations reachable |
| 4 | Complete email vertical slice in `features/mail/*` and `components/HowItWorks.tsx`; reusable report/input primitives only when another consumer needs them | 1, 3 | Input-to-result flow including invalid file, pending, error, clean, malicious and insufficient evidence; keyboard behavior |
| 5 | Website and file/link adaptation in `features/webcheck/*`, `features/forensics/*`, `components/charts/*` only as needed | 4 | Authorization and consent intact; specific evidence views preserved; long URL/hash/file name layouts pass |
| 6 | Detection, Bitcoin, guides, History, Settings and Auth visual consistency; no backend or auth rewrite | 3–5 | Local-only restrictions; all meaningful result states; deletion and session behavior unchanged |
| 7 | Optional public docs route improvement, isolated to router/docs/public shell with compatibility tests | 2, 6 | Anonymous hosted docs work; app routes still protected; no local `/docs` collision |
| 8 | Integration, accessibility, responsive, copy and performance review; remove unused assets/code only after reference checks | Prior adopted phases | Test outputs, state matrix, before/after screenshots, remaining limitations |

Do not perform a one-shot replacement of the entire frontend. Do not copy the prototype's vanilla DOM code into React. Implement its composition using existing data flow and reusable components.

New components may include `ToolInputLayout`, `ReportHeader`, `FindingRow`, `EmptyState` and `RecentResults`, but introduce a shared abstraction only when its responsibilities are clear. Different domain reports should not be forced into an oversized configurable component.

## 8. Definition of done

### User-facing acceptance

- Product purpose, primary action and real sample evidence are visible in the first desktop viewport.
- Home adds task context and recent work; it does not repeat the entire sidebar as equal cards.
- At 1440×900, each main tool exposes its primary input and action without a long introduction. Mobile puts the input before optional explanation.
- Each result has a distinct summary, evidence and next step. Unsupported or uncertain outcomes never resemble success.
- Every destination is reachable on mobile and with a keyboard. Focus remains visible and moves meaningfully after navigation, errors and result arrival.
- Check 360, 390, 768, 1024 and 1440 CSS px. No horizontal page scroll; long technical strings wrap or have labeled local scrolling. Verify 200% text zoom.
- Light and dark themes have deliberate surface hierarchy. Normal text contrast target ≥4.5:1; large text and interactive boundaries ≥3:1 where applicable. Status always has words/icons as well as color.
- Honor reduced motion. Essential content is visible before intersection observers run and if animation code fails.
- Mobile controls target 44×44 CSS px; keyboard alternatives exist for uploads and any drag interaction.
- No invented measurements, reports, live status, endorsements or product capabilities.

### Runtime and state matrix

Review both modes, not only the prototype mode switch. Include local engine unavailable; hosted unauthenticated redirect and post-sign-in return; expired session; 429 retry; busy service; failed request; invalid/oversize upload; pending; empty/partial/result states; saved/disabled/failed history; destructive confirmation; missing history record.

### Automated checks for implementation

From `frontend/`:

```sh
npm run lint
npm run typecheck
npm run test
npm run build
```

The build empties and rewrites `src/kestrix/server/static/`. That is expected when validating implementation, but keep this design folder out of the build output. Inspect generated changes before staging.

Relevant existing tests include `app/dashboard.test.tsx`, `app/hosted.test.tsx`, `features/landing/LandingPage.test.tsx`, `features/mail/MailPage.test.tsx`, `features/webcheck/WebcheckPage.test.tsx`, `components/HowItWorks.test.tsx`, `components/ui.test.tsx`, and `lib/api*.test.ts`.

Update assertions that intentionally describe old composition; retain tests for behavior, consent, capabilities, authentication and accessibility. Add meaningful tests for new behavior such as recent-result states, filters, selected File/Link deep links and mobile menu focus. Do not add tests that merely repeat CSS class names.

Only if server behavior or route contracts change, add targeted repository checks:

```sh
uv run pytest tests/server/test_history.py tests/server/test_hosted_auth.py tests/server/test_hosted_tokens.py tests/server/test_hosted_hardening.py tests/server/test_hosted_spa.py
```

Run before/after browser checks using `/browse`, as requested in this repository. Record screenshots with the same viewport, theme, mode and data. No claim of a performance improvement without measurement; compare initial route payload and layout shifts to the baseline, and ensure decorative scripts no longer run on analytical screens.

## 9. Review gate

Judge foundation slices by their stated exit criteria; Phase 1 intentionally changes tokens and primitives before composition. Reject a completed composition phase or the overall redesign if it is only a recolor or still repeats the old structure. Reject any slice that hides inputs beneath explanations, shows synthetic activity as real, weakens mode/consent boundaries, breaks mobile/keyboard navigation or omits a necessary state within its scope.

Accept a slice when its intended user task is clearer, its screenshots match the proposed composition, and its relevant behavior checks pass. A tasteful screenshot by itself is not completion.
