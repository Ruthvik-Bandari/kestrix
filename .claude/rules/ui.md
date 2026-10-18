---
paths:
  - "frontend/**"
---

# Dashboard (React + Vite)

- Verify with `npm --prefix frontend run lint && npm --prefix frontend run typecheck && npm --prefix frontend run test && npm --prefix frontend run build`. The build writes into `src/kestrix/server/static/`.
- The dashboard must work offline under the server's CSP (`default-src 'self'`): no CDN scripts, fonts or styles; bundle everything.
- Display replay metrics, heuristic scores and model text as separately labeled values. Never show a heuristic or ranking score as confidence or probability.
- Show abstained, unsupported, insufficient_evidence and engine-error states explicitly; do not render them as "no matches" or "safe".
- Render rule text, log fields, file names, URLs and model summaries as plain text (no `dangerouslySetInnerHTML`); they are untrusted.
- The browser talks only to the application origin (`/api`); no direct calls to Elasticsearch, mempool.space or the model API.
- Show before any action that sends data off the machine (website check, chain lookup, guardian) that it will do so.
