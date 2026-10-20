# Releasing kestrix-scan and kestrix

Both packages are versioned together while the version is below 1.0 (ADR 0006). A release is a `v*` tag
on `main`; [`.github/workflows/release.yml`](../.github/workflows/release.yml) then:

1. checks that the tag equals the `version` in `pyproject.toml` and `packages/kestrix-scan/pyproject.toml`;
2. builds the dashboard and both packages (`uv build --all-packages`);
3. records a build provenance attestation for every file in `dist/` (`actions/attest-build-provenance`);
4. publishes `kestrix-scan`, then `kestrix`, to PyPI with trusted publishing, from the `pypi` environment.

No PyPI API token exists anywhere: PyPI accepts the upload because the GitHub OIDC token says it comes from this
repository, this workflow file and the `pypi` environment.

## One-time setup (owner)

Do this once, before the first tag. Neither project exists on PyPI yet, so each needs a **pending** trusted
publisher, which creates the project on its first upload.

1. Sign in to PyPI with the account that should own the projects, with two-factor authentication on.
2. Go to **Your account → Publishing** (<https://pypi.org/manage/account/publishing/>) and, under
   **Add a new pending publisher → GitHub**, add these two publishers:

   | PyPI project name | Owner | Repository name | Workflow name | Environment name |
   | --- | --- | --- | --- | --- |
   | `kestrix-scan` | `Ruthvik-Bandari` | `kestrix` | `release.yml` | `pypi` |
   | `kestrix` | `Ruthvik-Bandari` | `kestrix` | `release.yml` | `pypi` |

   A pending publisher does not reserve the name: until the first upload, someone else can register it.
   Tag the first release soon after adding them.
3. In GitHub, create the environment: **Settings → Environments → New environment**, named `pypi`. Recommended:
   add yourself as a required reviewer, and under **Deployment branches and tags** allow only tags matching
   `v*`. The publish job then waits for your approval after the build and attestation succeed.
4. Optional, also recommended: under **Settings → Rules → Rulesets**, protect `v*` tags so only you can
   create them.

After the first successful upload, PyPI turns each pending publisher into a normal trusted publisher of that
project; nothing else needs to change for later releases.

## Cutting a release

1. Set the same version in `pyproject.toml`, `packages/kestrix-scan/pyproject.toml`, the `kestrix-scan==` pin
   in the root `dependencies`, `src/kestrix/__init__.py`, `packages/kestrix-scan/src/kestrix_scan/about.py`,
   the plugin's `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`.
   `packages/kestrix-scan/tests/test_claude_plugin_content.py::test_versions_match_everywhere` checks they agree.
2. Move the `Unreleased` entries of `CHANGELOG.md` and `packages/kestrix-scan/CHANGELOG.md` under the version.
3. Run `uv lock`, then the full check from the repository root:

   ```bash
   uv sync --all-extras && uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q
   ```

4. Merge to `main`, wait for CI, then tag and push the tag:

   ```bash
   git tag -s v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

5. Approve the `pypi` deployment in the workflow run. Check both project pages and the attestations under
   the repository's **Actions → Attestations**.

## Verifying a release

Anyone can check that a wheel was built by this repository's release workflow:

```bash
pip download --no-deps kestrix-scan==0.1.0 -d /tmp/k
gh attestation verify /tmp/k/kestrix_scan-0.1.0-py3-none-any.whl --repo Ruthvik-Bandari/kestrix
```
