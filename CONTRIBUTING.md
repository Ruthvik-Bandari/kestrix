# Contributing

This page covers how to set up Kestrix for development, which checks a change must pass, and the conventions the code follows. It is for anyone sending a fix, a test or a new check. To report a vulnerability, use [SECURITY.md](SECURITY.md) instead of an issue. Participation follows the [code of conduct](CODE_OF_CONDUCT.md).

## Set up

You need:

- Python 3.12 or newer (`.python-version` pins 3.12);
- [uv](https://docs.astral.sh/uv/);
- Node.js 24 (from `frontend/.nvmrc`) for the dashboard;
- Docker for the detection-repair engine tests.

```bash
git clone https://github.com/Ruthvik-Bandari/kestrix.git kestrix
cd kestrix
uv sync --all-extras                 # runtime, [ai], [exif] and dev dependencies from uv.lock
uv run kestrix detect engine-up    # pinned Elasticsearch 8.19.3 on 127.0.0.1:9200
uv run kestrix detect engine-status
npm --prefix frontend ci
```

Add dependencies with `uv add` (or `uv add --dev`), so `uv.lock` stays the source of truth. Commit the updated lock file.

## Layout

| Path | Contents |
| --- | --- |
| `src/kestrix/core/` | Shared reason codes, safe loading, outbound URL checks, config and secrets, evidence |
| `src/kestrix/detect/` | Sigma detection repair; bundled cases in `detect/cases/` |
| `src/kestrix/forensics/` | File and URL analysis |
| `src/kestrix/webcheck/` | Passive website check |
| `src/kestrix/bitcoin/` | Address decoding, risk, migration plans, guardian |
| `src/kestrix/server/` | FastAPI app; the built dashboard goes into `server/static/` |
| `src/kestrix/cli.py` | The `kestrix` entry point |
| `packages/kestrix-scan/` | The code scanner and Claude Code plugin; `plugin-repo/` holds the standalone plugin repository's own files |
| `frontend/` | React dashboard source (Vite) |
| `tests/` | `tests/<module>` per `kestrix` module, `tests/<package>` per research package, shared data in `tests/fixtures/` |
| `scripts/` | Generators (cases, docs, plugin repository) and checks |
| `src/kestrix*bench`, `src/kestrixvul` | Research packages, not in the wheel |
| `research/` | Cluster jobs (`hpc/<track>/`), published aggregates (`results/`), scanner benchmark cases (`scanbench/`), measurement tools (`scripts/`) |
| `docs/` | Module guides, API, security model, ADRs, research write-ups |

Each module keeps its logic in plain functions. Its `cli.py` and `api.py` are thin adapters over those functions, and business logic lives in neither.

## Checks

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs these. Run them before you open a pull request.

```bash
# Python lint and types
uv run ruff format --check src tests scripts
uv run ruff check src tests scripts
uv run mypy

# Python tests: unit tests, then engine tests against the pinned Elasticsearch
uv run pytest -m "not engine" --cov=kestrix --cov-report=term-missing
KESTRIX_ES_URL=http://127.0.0.1:9200 uv run pytest -m engine -v

# Dashboard
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend run test
npm --prefix frontend run build      # writes the bundle into src/kestrix/server/static/

# Package
uv build
```

- A plain `uv run pytest` runs everything. Engine tests are skipped automatically when Elasticsearch is not reachable, and the skip reason says so.
- CI runs the unit tests on Python 3.12 and 3.13, and runs the engine tests against the pinned image as a service container.
- The package job installs the built wheel in a clean environment, then runs `kestrix version`, `kestrix detect cases` and a Bitcoin scan. It also checks that the dashboard is inside the wheel.

For live dashboard work, run `uv run kestrix dashboard --no-open` and `npm --prefix frontend run dev` side by side. The Vite dev server proxies `/api` to port 8765.

## Conventions

- **Typed.** Python is checked with strict mypy. Use precise types, Pydantic models at API boundaries, and frozen dataclasses for internal records. A `# type: ignore` needs a specific error code.
- **No dead code.** Remove unused functions, parameters, flags and commented-out code. Do not add options nothing uses yet.
- **A test per behavior.** Every behavior change or bug fix comes with a test that fails without it. Name the test after the behavior it pins, such as `test_validation_must_be_independent_of_development`.
- **Engine-marked tests.** Any test that needs Elasticsearch carries `@pytest.mark.engine` (or a module-level `pytestmark`). Matching claims come from replay on the pinned engine. Do not add a Python matcher as a stand-in for it.
- **Explicit outcomes.** Errors are `Rejected(Reason.X, detail)` from `core/errors.py`, never an empty result. Add a new `Reason` only when no existing code fits, and map its HTTP status in `server/app.py` if it is not a 400.
- **Untrusted input stays data.** Load YAML only through `core/safe_load.py`. Bound sizes and depth. Never `eval`, `exec` or `pickle` input. Outbound requests go through `core/netguard.check_url`.
- **Synthetic fixtures only.** Tests use fixtures in the repository. Do not commit real telemetry, keys or personal data.
- **Docs follow code.** When a command, flag, field, limit, exit code or reason code changes, update the module page under `docs/modules/`, `docs/api.md` or `docs/security-model.md` in the same change.

## Bundled detection cases

The cases in `src/kestrix/detect/cases/` are generated. Do not edit them by hand. Change [`scripts/build_detect_cases.py`](scripts/build_detect_cases.py), then regenerate and run the engine tests:

```bash
uv run python scripts/build_detect_cases.py
uv run pytest -m engine
```

Every case must reach the `expected` outcome in its `case.yml`. All case events must stay synthetic (`provenance: synthetic`).

## Improving a scanner rule

Several `kestrix-scan` rules ship with thin evidence; [the list](docs/modules/code.md#limits) says which. The most useful contribution for one of them is a real case:

- **A miss:** a vulnerable snippet the rule should flag (from a public fix commit or advisory, with the link), added as a positive test next to the rule's other tests in `packages/kestrix-scan/tests/`.
- **A false alarm:** safe code the rule flags, added as a negative test.
- **A fix:** the smallest rule change that makes the new test pass without breaking the others.

Rules change on test evidence like this, and every benchmark rerun reports the new numbers. Do not paste private or proprietary code.

To report a rule result without a fix, open an issue with the **Scanner rule: false positive or missed finding** template.

## Good first contributions

Small, self-contained tasks that need only `uv sync --all-extras` and `uv run pytest packages/kestrix-scan/tests`:

- **A negative test for a rule kept without evidence.** `c.random.rand`, `c.format.nonliteral` and
  `html.inline.event_handler` are kept because they were requested, with no measured detection
  ([code.md](docs/modules/code.md#limits), [CVE-fix benchmark](docs/benchmarks/cvefixes.md)). Each has only a few
  negative cases. Add a safe snippet the rule must not flag, next to its tests in
  `packages/kestrix-scan/tests/test_systems_rules.py` or `test_web_rules.py`; if the rule flags it, that is a false
  positive to fix or report.
- **A positive test from a public fix** for a rule in the [Limits](docs/modules/code.md#limits) list, such as
  `go.exec.command` or a `cs.*` rule: the vulnerable lines from a public advisory or fix commit, with its link.
- **A docs fix.** A command, flag or output in `docs/modules/*.md` or a README that no longer matches what the CLI
  prints. Change the doc in the same pull request as a test, if the behavior is testable.
- **"When to use" and "When not to use" sections** in the `secure-code-review` skill
  (`packages/kestrix-scan/src/kestrix_scan/claude_plugin/kestrix/skills/secure-code-review/SKILL.md`), which the
  [plugin submission notes](docs/plugin-submission.md) list as missing.

## Commits and pull requests

Use a short area prefix and an imperative summary, loosely following Conventional Commits:

```text
detect: reject chained modifiers before conversion
webcheck: re-validate the Location host on every redirect
docs: document the chunked-body limitation
```

Common prefixes are the module names (`detect`, `forensics`, `webcheck`, `bitcoin`, `server`, `frontend`), plus `core`, `docs`, `ci`, `chore` and `test`. Keep one logical change per commit. In the pull request, say what changed, why, and which commands you ran.

Contributions are accepted under the [Apache License 2.0](LICENSE).
