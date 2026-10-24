# Kestrix design specification — proposed

This is the implementation reference for the accompanying design proposal. It is not a replacement for root project instructions or verified product contracts. Preview control chrome and synthetic activity belong only to the design artifact.

## Visual intent

Precise, grounded, calm. The public first impression should be memorable through composition and product evidence. The working interface should make technical information easier to scan.

Use a dark graphite hero with left-aligned, generously scaled type and a readable report on the right. Follow it with off-white sections of different compositions: compact tool rows, a three-step process, a split trust section. Use solid panels and strong grouping in the app.

Avoid holographic/glass treatments, purple gradient titles, neon outlines, animated binary wallpaper, arbitrary giant outline numbers, decorative threat maps and generic nine-card dashboards. Avoid presenting every container as a raised card. Use spacing and dividers before adding borders and shadows.

## Typography

Keep the current self-hosted assets:

- **IBM Plex Sans:** headings, prose, navigation, controls. Weights 400, 500, 600; selective 700.
- **IBM Plex Mono:** hashes, domains, code, dates, fixture IDs and compact metadata. Weights 400 and 500.

| Role | Desktop | Mobile | Notes |
|---|---|---|---|
| Public hero | 64–76px / 1.04 | 40–46px / 1.06 | Weight 500–600, tracking about -0.045em, intentional line breaks |
| Public section | 36–44px / 1.12 | 28–32px / 1.15 | 20–26ch maximum |
| App page title | 30–34px / 1.2 | 26–28px / 1.2 | Solid text, no gradients |
| Report verdict | 26–32px / 1.2 | 24–28px / 1.2 | Outcome label paired with semantic icon |
| Subheading | 18–20px / 1.35 | 18px / 1.35 | Weight 600 |
| Body | 15–16px / 1.55 | 16px / 1.55 | 60–72ch reading width |
| Labels/table | 13–14px / 1.45 | 14px / 1.45 | No critical instructions in tiny type |
| Metadata/eyebrow | 11–12px / 1.5 | 12px / 1.5 | Uppercase only for short section labels |

Use tabular numerals for comparable counts. Code and evidence must wrap safely; never shrink an entire report to fit a long URL.

## Color tokens

Map these values to the existing semantic CSS variables rather than layering another competing theme on top. Remove obsolete definitions after confirming consumers. Use tested semantic pairings, not severity colors as a universal brand palette.

| Token / purpose | Light | Dark |
|---|---|---|
| `--bg` page | `#f5f6f2` | `#101918` |
| `--surface-solid` panel | `#ffffff` | `#172421` |
| `--inset` secondary surface | `#edf1eb` | `#20322d` |
| `--rail` navigation | `#eef1eb` | `#131f1b` |
| `--ink` primary text | `#162320` | `#edf4ed` |
| `--ink-2` secondary text | `#586860` | `#afc0b6` |
| `--line` divider | `#d8e0d6` | `#354a40` |
| `--line-strong` controls | `#7d8d82` | `#789285` |
| `--accent` action | `#0c6b4b` | `#8ce4bd` |
| `--accent-hover` | `#075338` | `#b0efcf` |
| `--on-accent` | `#ffffff` | `#10271c` |
| `--focus` | `#0c6b4b` | `#c6ef9b` |
| High/critical text | `#a12c35` | `#ffb4b8` |
| High/critical surface | `#fff1ef` | `#3b2024` |
| Medium text | `#805000` | `#efcd8b` |
| Medium surface | `#fff4db` | `#3a2d16` |
| Success text | `#14623e` | `#9ce5bb` |
| Success surface | `#e9f5ec` | `#193c2b` |

Hero background remains `#101918` in both themes, with text `#edf4ed`, muted text `#afc0b6`, and optional lime `#c6ef9b`. Accent green is for actions/current location; lime belongs to the public composition. Informational and low-severity statuses can use neutral or a restrained blue pairing verified for contrast. Distinguish Critical/High/Medium/Low/Info in text even when two severities share a family of colors.

The preview is a composition reference. If contrast verification requires a token adjustment, document it and update both the visual reference and implementation. Never preserve an inaccessible pair just to match a screenshot.

## Layout and spacing

- Base unit 4px. Normal steps: 4, 8, 12, 16, 24, 32, 48, 64, 80, 96.
- Public maximum width 1200px, 48–64px desktop gutters, 20px mobile gutters.
- Public section spacing 72–96px desktop, 40–56px mobile, varied by relationship rather than one repeated chapter template.
- App rail about 224px; main content padding 32–40px desktop, 16–20px mobile.
- Comfortable app content maximum width about 1320px. Do not artificially center a small card inside a mostly empty work area.
- Tool input/report split about 360px + flexible report when the content supports it; collapse below about 1100px. Report-only pages use the full content area.
- Panel padding 20–24px; row gap 12–16px; table rows about 52–60px.
- Controls radius 6px; panels 12px; status pills use compact rounded shapes. Do not use large pills for every navigation item.
- Default elevation: none. Use a soft shadow only for a floating menu/dialog or the featured public report.

## Components and states

| Component | Rules |
|---|---|
| Primary button | Solid action color, explicit verb, 44px target, visible focus, pending label and disabled semantics; no gradient |
| Secondary action | Quiet border or text treatment; visually subordinate; no row of equally weighted CTAs |
| Navigation | Group labels, clear current page, actual link destinations; use familiar icons sparingly |
| Input | Persistent label, example as hint, error association, visible focus, optional fields grouped; preserve submitted value on error |
| File input | Clickable picker as well as drag/drop; show accepted format and mode-specific size; selected file and removal control |
| Findings | Severity icon+label, short title, evidence disclosure, reason code inside detail; filters show truthful counts |
| Summary | Actual verdict, compact context, primary next step. “Clean” is rendered as “No checks fired” where clarification is needed |
| Table | Semantic headers, row links with useful labels, date/time formatting; mobile prioritizes result and tool without losing access to other columns |
| Empty state | Explain why empty and offer one useful action; no fabricated chart or zero-risk claim |
| Error state | State what failed, retain input, offer available retry/recovery; no raw stack traces |
| Pending | Indeterminate state with task description; use real progress only if the API supplies it |
| Help | Collapsible context; short analytical limitations stay close to the relevant result |
| Dialog | Focus containment and return, Escape where safe, clear destructive confirmation; reuse existing implementation |

For `HowItWorks`, change only the first-visit default; retain stored open/closed preferences. Avoid hiding necessary authorization or processing details when collapsing general education.

## Responsive behavior

- **≥1200px:** full public two-column hero; application rail; appropriate report/input split.
- **768–1199px:** reduce gutters; allow report below input; compact public navigation before it crowds the logo/action.
- **<768px:** one-column pages; disclosure/navigation drawer with keyboard support; full-width input and primary action where helpful; summary before evidence; source context after prioritized findings.
- At 360 and 390px, no horizontal document overflow. Technical detail may use a clearly contained horizontal scroll area. A source URL is text, not an automatic outbound link.
- Test 200% text zoom. Do not hide controls, verdicts or errors to preserve a desktop composition.

## Motion and accessibility

Use 120–180ms color/focus transitions and at most 200–240ms disclosure transitions. Do not animate whole report panels continuously. Honor `prefers-reduced-motion`; content stays visible without JavaScript animation observers. Maintain skip navigation, document title, heading order, route focus, result announcements and upload keyboard alternatives.

Use native links, buttons, details and labeled controls where suitable. A visually attractive control with no behavior is not acceptable. Show all important state through text as well as color. Avoid smooth scrolling when reduced motion is requested.

## Copy and truth

Lead with a task or outcome, use direct verbs, and remove duplicated explanations. Prefer “Check an email,” “Review evidence,” “View local setup” and “Download report” over vague “Discover,” “Explore more” or “Get protected.”

Approved product facts must come from current source and docs. The design does not authorize claims of automatic containment, continuous monitoring, guaranteed safety, measured detection accuracy, live integrations or published package availability.

Mode-specific copy should say where processing occurs. Reports retained for 30 days are distinct from raw uploads not retained. Heuristics do not measure probability. Suggested next steps are advice, not completed remediation.

## Artifact-to-production mapping

| Preview view | Production destination |
|---|---|
| Website | `features/landing/*`, public shell, mode-aware CTA helpers |
| Workspace | `app/Layout.tsx`, `features/home/HomePage.tsx`, existing history query |
| Email report | `features/mail/*`, history report detail; actual API output |
| Design system | Development reference/specimens; not a new customer-facing product page |

Do not port the prototype toolbar, sample table data, mode selector, temporary mark or preview dialogs into production by accident.

The source-message illustration is available only because the bundled synthetic fixture includes the original message. `MailReport` does not contain the full body, Reply-To or source date. For actual report/history views, replace that illustration with available subject/from/hash metadata and findings. Do not extend retention or input parsing to reproduce an illustrative panel. The curated next step is proposed UI copy, not a backend-provided recommendation field.

## Tool page template

Every tool and guide page shares one frame (`components/toolframe.tsx`, `features/tools/ToolHeader.tsx`, wording in `features/tools/frame.ts`):

- **Header band:** icon tile, name, one-line purpose with the in-app docs link, capability chips (where it runs, limits, what it never does), the user's own saved-report count and latest verdict when history is on and has results for that tool, and a three-step rail (Add the input, Read the evidence, Decide) whose current step follows the page's real state.
- **Body:** a 24rem numbered workspace column beside a flexible report column from 1100px; stacked, input first, below. Before a result the report column shows an outline of the report's sections (headings only); after one it shows the report and the workspace column adds a sticky jump list.
- **Report sections** use `ReportSection` (icon, heading, count); findings carry a left severity rule next to the severity icon and label; evidence sits in a labelled monospace inset.
- Guide pages use the same band with a link rail (Set it up, Use it, Fix problems) and a two-column checklist.

## Emerald direction (2026-10-22)

Owner-chosen visual reference: a third-party Dribbble shot of a fictional security product, used for style only and kept out of the repository because it is someone else's artwork. Replaces the graphite/lime hero and the code rain. Tokens live in `frontend/src/index.css`; `.scope-dark` re-applies the dark set inside a light page (the landing opening).

| Token | Light | Dark |
|---|---|---|
| `--bg` / `--rail` | `#f1f7f3` / `#e7f0ea` | `#040a07` / `#060e0a` |
| `--surface-solid` / `--inset` | `#fbfdfc` / `#e4efe8` | `#0a1712` / `#0f2019` |
| `--line` (hairline) | `#cddcd2` | `rgb(61 220 142 / .17)` |
| `--line-strong` (controls) | `#68887a` | `#5a8571` |
| `--ink` / `--ink-2` / `--ink-3` | `#0c1f17` / `#46604f` / `#4e695a` | `#e9f5ee` / `#a9c2b4` / `#8aa597` |
| `--accent` / hover | `#0b6b45` / `#085536` | `#1fd17a` / `#4be59a` |
| `--on-accent` | `#ffffff` | `#03140b` |
| `--accent-text` / `--accent-soft` | `#0b6b45` / `#d9eee1` | `#3ddc8e` / `#0f2e21` |
| `--focus` | `#0b6b45` | `#5cf0a8` |
| `--glow` | soft emerald halo | `0 0 22px -2px rgb(31 209 122 / .45)` + 1px ring |
| severity | unchanged (red/amber/blue, icon + label) | `ok-bg` darkened to `#143a28` |

Contrast (WCAG, computed): dark ink 16.4 on surface, ink-2 9.7, ink-3 6.4 on inset (lowest), accent-text 8.3 on accent-soft (lowest), on-accent 9.4 on accent; light ink-2 5.9 on rail (lowest), ink-3 4.6 on inset after retune, accent-text 5.4 on accent-soft, on-accent 6.6 on accent. Every severity text on its tint is 6.2 to 8.8. Control borders 3.3 to 4.8, focus 6.0 to 13.8, marks 3.5 to 9.2. Button labels on emerald are dark (not white) because white on bright emerald is about 2:1.

Components: primary button = solid emerald with halo and a light icon square on the right (`ButtonIcon`, `Button icon=`); secondary = translucent dark fill, hairline, darker icon square; `Pill` badge (dot + label); `panel-glow` only on the featured example and sign-in card; active nav gets an emerald gradient and glowing left edge; tool header band has a static corner beam/circuit motif. Landing: rounded frame on a darker field, beams (CSS gradients), `CircuitDial` (inline SVG: traces, nodes, tool icon nodes, tick dial, BrandMark emblem). Motion: a slow pulse along three traces and a breathing dial halo on the landing only, both off under `prefers-reduced-motion`; sign-in and the app are static. No inline style strings (CSP `style-src 'self'`).
