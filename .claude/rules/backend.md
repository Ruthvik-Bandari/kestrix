---
paths:
  - "src/kestrix/server/**"
  - "src/kestrix/*/api.py"
---

# Local API server (FastAPI)

- Verify with `uv run pytest tests/server` plus the module's API tests, then the full `uv run pytest`.
- The server is single-user and loopback-only. Keep the `_LocalOnly` middleware in `server/app.py` in front of every route: Host allowlist (421), cross-site write refusal via `Origin` / `Sec-Fetch-Site` (403), and per-route body caps (413). A new large-body route needs an entry in `LARGE_BODY_ROUTES` and a streaming or field-level limit.
- Routes stay thin: validate the body with a Pydantic model (`extra="forbid"` for new models), call the module function, return its model.
- Errors are `Rejected(Reason, detail)` rendered as `{reason, detail}`. Map any non-400 reason in `_STATUS`. Never leak stack traces.
- `GET` routes must have no side effects. Do not add CORS headers.
- Never return or log the Anthropic key; settings routes report only whether it is configured.
- Keep the security headers on every response, including refusals.
- Document every route change in `docs/api.md` in the same change.
