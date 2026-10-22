# Submitting the Claude Code plugin

How to publish the `kestrix` plugin to Anthropic's plugin directory and to community marketplaces: the field values
for the submission form, the behaviors to disclose, the pre-submission checklist mapped to evidence, and the steps
for the owner. Roadmap item 8 of [the competitive landscape](research/competitive-landscape-2026-10.md).

Nothing here has been pushed or submitted. The plugin repository,
[Ruthvik-Bandari/kestrix-claude-plugin](https://github.com/Ruthvik-Bandari/kestrix-claude-plugin), exists, is private
and is empty; its content is generated into `dist/claude-plugin-repo/` by `scripts/build_plugin_repo.py`.

## Sources

Read on 2026-10-20. Re-read them before submitting; the portal's rules change.

- Pre-submission checklist: <https://claude.com/docs/plugins/pre-submission-checklist>
- Publish to the directory (plans, roles, review): <https://claude.com/docs/directory/publish>
- Submit your plugin (the form, private repositories, updates): <https://claude.com/docs/plugins/submit>
- Create a marketplace: <https://code.claude.com/docs/en/plugin-marketplaces>
- Plugins and the manifest reference (fields, directory listing fields, `userConfig`):
  <https://code.claude.com/docs/en/plugins>, <https://code.claude.com/docs/en/plugins/manifest-reference>
- Plugin evals (`claude plugin eval`): <https://code.claude.com/docs/en/plugin-evals>
- Trail of Bits curated marketplace: <https://github.com/trailofbits/skills-curated> (its `README.md` and
  `CLAUDE.md`, which is its contributing guide; it has no `CONTRIBUTING` file)

## The plugin repository

`uv run python scripts/build_plugin_repo.py` writes 112 files (about 260 KB) to `dist/claude-plugin-repo/`:

```text
.claude-plugin/plugin.json        1,013 B   manifest (name kestrix, displayName Kestrix, 0.1.0, Apache-2.0)
.claude-plugin/marketplace.json     970 B   self-hosted marketplace "kestrix", source "./"
.gitignore                           83 B   evals/results/
CHANGELOG.md  LICENSE  NOTICE  PRIVACY.md  README.md  SECURITY.md
benchmarks/                                 scorecard and A/B report (text)
evals/                                      claude plugin eval suite: 4 cases and the A/B cases, README with results
scripts/ab_eval.py                          runs the A/B comparison (needs your usage; not run by the build)
hooks/hooks.json                  1.6 KB
hooks/kestrix_hook.py            37.9 KB   the only script the hooks run (standard library)
skills/                                     6 skills (3 are the /kestrix:* commands); largest file 43.6 KB
tests/test_no_network.py          4.6 KB   stdlib unittest: every hook with sockets refused
```

The `hooks/` and `skills/` files are the packaged plugin byte for byte (`kestrix_scan.plugin.plugin_files()`).
`tests/integrations/test_claude_plugin_repo.py` checks that, that two builds are identical, and every checklist rule
the build enforces. The repository-only files live in `packaging/claude-plugin-repo/`; edit them there, never in
`dist/`.

## Directory submission form

The portal reads the listing from `plugin.json` and the README, so the values below are already in those files. To
change one, edit `packaging/claude-plugin-repo/` or the packaged `plugin.json`, rebuild, push and re-validate.

| Field | Value |
| --- | --- |
| Submission type | **Plugin bundle** |
| Repository | `https://github.com/Ruthvik-Bandari/kestrix-claude-plugin` |
| Plugin path | empty (the plugin is at the repository root) |
| Branch or tag | `main`, or the release tag `kestrix--v0.1.0` to publish only tagged releases |
| Name | `kestrix` |
| Display name | `Kestrix` |
| Short description | `Kestrix security for Claude Code: scans every file Claude writes with the local kestrix-scan scanner and has Claude fix the findings, plus secure-review skills and /kestrix:scan, /kestrix:fix and /kestrix:review. Runs locally; needs the kestrix-scan (or kestrix) command on PATH.` (from `plugin.json`) |
| Long description | `README.md` (the directory shows the README as the listing's description) |
| Category | `security` (the marketplace entry's `category`; the portal docs list no separate category field) |
| Keywords | `security`, `sast`, `secrets`, `code-review`, `cwe`, `hooks`, `kestrix` |
| Homepage | `https://github.com/Ruthvik-Bandari/kestrix-claude-plugin` |
| Documentation | `https://github.com/Ruthvik-Bandari/kestrix-claude-plugin#readme` (`documentationUrl`) |
| Support | `https://github.com/Ruthvik-Bandari/kestrix-claude-plugin/issues` (`supportUrl`) |
| Privacy policy | `https://github.com/Ruthvik-Bandari/kestrix-claude-plugin/blob/main/PRIVACY.md` (`privacyPolicyUrl`) |
| License | `Apache-2.0` (`plugin.json` and `LICENSE`) |
| Author / publisher | `Ruthvik Bandari` |
| Contact email (Compliance step) | `<support contact email>`: an address Anthropic can reach about the submission |

**Data handling step:**

| Question | Answer |
| --- | --- |
| Reads or stores personal data? | It collects no personal data. It reads the source files Claude edits in the user's project and keeps copies of them, and the list of changed paths, in the plugin's local data directory for up to 14 days. Nothing leaves the machine. |
| Sends data to services other than its declared connectors? | No. The plugin declares no connectors, and no hook makes a network request. The user-run `kestrix-scan db update` downloads public OSV data and sends nothing about the user. |
| How long it keeps data | Session records (changed paths, snapshots, Stop-gate counters) are deleted after 14 days, and the whole data directory when the plugin is uninstalled. |
| Intended for people under 18? | No; it is a developer tool. |

## Disclosed behaviors

Everything the plugin runs, reads, writes or fetches. The README and PRIVACY.md state each one.

1. **Runs** `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/kestrix_hook.py" <event>` on `SessionStart`, `PreToolUse`
   (`Write|Edit|MultiEdit|NotebookEdit` and `Bash`), `PostToolUse` (`Write|Edit|MultiEdit|NotebookEdit`) and `Stop`.
2. **Starts** the `kestrix-scan` executable on the user's PATH (or `kestrix code scan` when only the workbench is
   installed) with the hook JSON on stdin. Never one in the project directory, never a shell, never an installer
   or package launcher.
3. **Reads** the file being changed (up to 1 MiB), `.kestrix.json` and `[tool.kestrix]` settings, and the local OSV
   index if the user built one.
4. **Writes** session records and file snapshots only to `${CLAUDE_PLUGIN_DATA}/sessions/` (or a private 0700 temp
   directory), deletes them after 14 days.
5. **Returns** to Claude Code: one context line at session start, findings as `additionalContext` after an edit,
   a `deny` for a known-malicious package install, a `block` at Stop when the opt-in gate is on.
6. **Network:** none from hooks or the code-security skills. The only network command is the user-run
   `kestrix-scan db update` (OSV exports from `storage.googleapis.com`).
7. **The `kestrix-security` skill** may ask Claude to run commands of the separate Kestrix workbench that use the
   network when the user asks for them: `kestrix webcheck scan` (up to 50 read-only GETs to the user's site, or one with `--page-only`, and a TLS handshake),
   `kestrix bitcoin scan --lookup-chain` (addresses and the user's IP to mempool.space, after the user agrees), and
   `kestrix detect engine-up` (Docker pulls the pinned Elasticsearch image). It tells Claude to offer, not run, an
   install of the workbench (`uv tool install kestrix`).
8. **Credentials:** none. No `userConfig`, no tokens read from the environment.
9. **Permissions:** the plugin does not change Claude Code's settings or permission rules.

## Pre-submission checklist, item by item

Results come from the checklist page. "Build audit" means `scripts/build_plugin_repo.py` refuses to build when the
rule is broken, and `test_the_checklist_audit_passes_and_catches_each_problem` proves each check fires.

| Checklist item | Status | Evidence |
| --- | --- | --- |
| Folder contains `.claude-plugin/plugin.json` | Pass | `dist/claude-plugin-repo/.claude-plugin/plugin.json`; plugin at the repository root |
| One plugin per submission | Pass | the marketplace lists one plugin |
| Hook files inside the plugin folder; component paths inside it | Pass | build audit (`_hook_problems`); `test_hooks_run_only_python3_on_the_bundled_script` |
| Regular files only (no symlinks, submodules, LFS) | Pass | the build writes regular files; `read_tree` compares them |
| No `.DS_Store`, `Thumbs.db`, `desktop.ini`, `__MACOSX` | Pass | build audit; `.gitignore` lists `.DS_Store` |
| Windows/macOS-safe names, no case-only clashes, plain folder names | Pass | build audit (`_name_problems`) |
| No `export-ignore`/`export-subst`/`filter` in `.gitattributes` | Pass | the repository has no `.gitattributes` |
| Repository < 50 MiB, < 10,000 files, each file < 5 MiB | Pass | 112 files, about 260 KB total |
| `name` lowercase, digits, hyphens, ≤ 64 chars | Pass | `kestrix`; `claude plugin validate --strict` |
| Distinctive name, not reserved, not presenting as official | Pass, pending portal | `kestrix`, the project's own name. The portal's **Validate** confirms no other organization uses it |
| `displayName`, `author.name` in one writing system | Pass | `Kestrix`, `Ruthvik Bandari` (ASCII) |
| Component keys spelled as the reference | Pass | no component keys in `plugin.json`; `hooks/hooks.json` loads by default |
| `description`, `author`, `version` set | Pass | `plugin.json`; `test_plugin_manifest_has_the_required_fields` |
| README ≥ 40 words outside code blocks | Pass | build audit; `test_readme_covers_what_the_directory_asks_for` |
| `LICENSE` file or `license` field | Pass | both; `LICENSE` is the Apache-2.0 text |
| Non-image files < 256 KiB | Pass | largest is `skills/fixing-security-findings/SKILL.md`, 43.6 KB; build audit |
| ≤ 512 files | Pass | 112; build audit |
| Text files only (no binaries) | Pass | build audit decodes every file as UTF-8 |
| Bundled images only through Markdown image syntax | n/a | no images yet; `scripts/record_demo.md` says how to add them |
| MCP servers declared with `command`/`url`, no bundles | n/a | no MCP servers |
| Launchers pinned; `uv run` with `--locked` | Pass (none used) | build audit greps the hook script for `npx`, `bunx`, `uvx`, `pnpm dlx`, `yarn dlx`, `pipx run`, `uv run`, `pip install`, `npm install` |
| No package-source config files (`.npmrc`, `uv.toml`, ...) | Pass | build audit |
| No real credentials; secrets only through sensitive `userConfig` | Pass (none needed) | no `userConfig` (build audit); `test_no_secrets_and_no_hardcoded_home_paths` runs the secret rules on the tree; the demo's fake token is assembled at run time (`test_setup_plants_a_fake_token_only_at_run_time`) |
| No credential read from the environment and sent to a server | Pass | the hook reads only `CLAUDE_PLUGIN_DATA`, `CLAUDE_PROJECT_DIR`, `KESTRIX_BLOCK_ON_STOP`, `KESTRIX_INSTALL_GUARD` (and PATH, temp dir); no network |
| `.mcp.json` valid; remote MCP over https | n/a | no `.mcp.json` |
| Hook command paths written from `${CLAUDE_PLUGIN_ROOT}` | Pass | `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/kestrix_hook.py" <event>` |
| No launchers or installs in hook scripts | Pass | build audit; the missing-scanner hint names no command line (`test_missing_kestrix_fails_open_with_one_hint`) |
| Reviewer hold: registry package / lockfile install | Not triggered | no launcher, no `package.json` or lockfile at the root (build audit) |
| Reviewer hold: program the validator can't read, in a subfolder plugin | Not triggered | the plugin is at the repository root, which is why the hook may run a Python file |
| `hooks/hooks.json` valid, documented events and types | Pass | `claude plugin validate --strict`; `test_hooks_cover_the_documented_events_and_tools` |
| `hooks/hooks.json` not listed in `plugin.json` | Pass | no `hooks` key |
| Valid front matter, `description` a single text value | Pass | `claude plugin validate --strict dist/claude-plugin-repo/skills`; `test_skill_frontmatter_is_valid` |
| Component folder and file names exact (`hooks/`, `skills/`, `SKILL.md`) | Pass | the same validation |
| Security scan: everything the plugin runs, sends or fetches is in the README | Pass | README "What the plugin runs" and "The one network action"; the list above |
| Security scan: readable source, nothing compiled or minified | Pass | one 917-line standard-library Python script and Markdown |
| Compare output with and without the plugin (`claude plugin eval`) | Done, 1 run per arm | `evals/README.md` "Results so far"; run the full suite before quoting numbers |
| Directory listing icon (`icon` in `plugin.json`, or `.claude-plugin/icon.png`) | Open, owner | Claude Code 2.1.307 `claude plugin validate --strict` passes but warns `ICON_MISSING`. It needs a square PNG or JPEG of 512 to 2048 px, under 2 MB. The build audit accepts only UTF-8 text files, so adding a logo means changing the audit and the packaged files; not done |
| Load the plugin on each surface | Owner | Claude Code only: the hooks are the core of the plugin. Check how claude.ai and Cowork list a hooks plugin after submission |

Local validation, 2026-10-21, Claude Code 2.1.307 (the same three commands also print the `ICON_MISSING` warning described above; the result line is `Validation passed`):

```text
$ claude plugin validate --strict dist/claude-plugin-repo
Validating marketplace manifest: .../dist/claude-plugin-repo/.claude-plugin/marketplace.json
✔ Validation passed
$ claude plugin validate --strict dist/claude-plugin-repo/.claude-plugin/plugin.json
✔ Validation passed
$ claude plugin validate --strict dist/claude-plugin-repo/skills
✔ Validation passed
```

## Owner steps

The main `Ruthvik-Bandari/kestrix` repository stays private until you decide otherwise. The plugin repository can be
public on its own: it holds only the plugin and its docs, and installs the scanner from PyPI. While the main
repository is private, the attribution links in three skills (`https://github.com/Ruthvik-Bandari/kestrix`) and
the PyPI project's source links return 404 to others.

1. **Publish `kestrix-scan` to PyPI first.** The plugin does nothing without the binary, and the README, the
   missing-scanner message and the `kestrix-security` skill all point to PyPI. Follow [release.md](release.md): add
   the pending trusted publishers, create the `pypi` environment, then tag `v0.1.0` on `main` of the main
   repository. Trusted publishing works from a private repository, but GitHub artifact attestations
   (`actions/attest-build-provenance` in `release.yml`) on a private repository need GitHub Enterprise Cloud; if
   that step fails, make the main repository public first or drop the attestation step for this release. Confirm with `pipx run --spec
   kestrix-scan==0.1.0 kestrix-scan --version` (or `pip install kestrix-scan` in a fresh venv).
2. **The repository exists** (private, empty): `https://github.com/Ruthvik-Bandari/kestrix-claude-plugin`. In its
   settings, turn on **Private vulnerability reporting** (Security → Advisories), which SECURITY.md relies on, and
   Issues, which `supportUrl` points at.
3. **Build and push** from this repository, on the commit you are releasing:

   ```bash
   uv sync --all-extras
   uv run python scripts/build_plugin_repo.py
   claude plugin validate --strict dist/claude-plugin-repo
   cd dist/claude-plugin-repo
   PATH="$PWD/../../.venv/bin:$PATH" python3 -m unittest discover -s tests -v
   git init -b main && git add -A && git commit -S -m "Kestrix plugin 0.1.0"
   git remote add origin git@github.com:Ruthvik-Bandari/kestrix-claude-plugin.git
   git push -u origin main
   ```

   Later builds keep `dist/claude-plugin-repo/.git`, so the next release is rebuild, commit, push.
4. **Tag a signed release** in the plugin repository:

   ```bash
   claude plugin tag --dry-run                 # checks plugin.json and the marketplace entry agree
   claude plugin tag -m "kestrix %s"           # creates kestrix--v0.1.0; signed, since tag.gpgsign is on
   git tag -v kestrix--v0.1.0
   git push origin kestrix--v0.1.0
   gh release create kestrix--v0.1.0 --repo Ruthvik-Bandari/kestrix-claude-plugin --verify-tag \
     --title "Kestrix plugin 0.1.0" --notes-file CHANGELOG.md
   ```

   Attach the demo recording to the release, not the repository (see `scripts/record_demo.md`).
5. **Make the repository public, after `kestrix-scan` is on PyPI:**

   ```bash
   gh repo edit Ruthvik-Bandari/kestrix-claude-plugin --visibility public --accept-visibility-change-consequences
   ```

   Then check from another account or a private window: `/plugin marketplace add
   Ruthvik-Bandari/kestrix-claude-plugin` and `/plugin install kestrix@kestrix` in a clean Claude Code.
6. **Run the eval suite** at the default 3 runs and update `packaging/claude-plugin-repo/evals/README.md` with the
   result (24 agent runs; the 1-run pass of the 4 cases cost about $0.50):

   ```bash
   cd dist/claude-plugin-repo
   PATH="$PWD/../../.venv/bin:$PATH" claude plugin eval . --allow-tools Write Edit --threshold 0.75 --no-publish
   ```

7. **Capture the screenshots and recording** with [scripts/record_demo.md](../scripts/record_demo.md).
8. **Submit at <https://claude.ai/directory/manage>** (Pro, Max, Team or Enterprise plan; Free cannot submit). Connect
   GitHub for the claude.ai organization that should own the listing, then **Submit new → Plugin bundle**, enter
   the repository, **Validate**, fix any **Blocking** finding and **Re-validate**, then fill the steps with the
   values above. A private repository can be validated and submitted (the portal asks to upload the source and needs
   the Claude GitHub App), but publishing needs it public. Keep **GitHub push webhook** on (needs admin on the repo).
   Raise `version` with every release; the directory picks up each commit on the tracked branch or tag.
9. **Propose to `trailofbits/skills-curated`.** Its README offers three routes; use route 2, an issue asking to add
   `Ruthvik-Bandari/kestrix-claude-plugin` to its approved-marketplace list:
   <https://github.com/trailofbits/skills-curated/issues/new>, titled "Marketplace approval:
   Ruthvik-Bandari/kestrix-claude-plugin". Route 3 (a pull request copying the plugin into their `plugins/`) would
   place the files in a repository licensed CC-BY-SA-4.0 and must meet their house rules (see below), so it is the
   weaker fit. Their review: at least one CODEOWNER approval, and every line of hooks and scripts is read and run
   locally; network calls without documented purpose, obfuscated code and self-promotional skills are rejected.
   Draft issue body:

   > Requesting review of Ruthvik-Bandari/kestrix-claude-plugin for the approved-marketplace list (route 2).
   >
   > **What it does.** After every Write or Edit, a PostToolUse hook runs the local `kestrix-scan` scanner (PyPI,
   > Apache-2.0, no dependencies on Python 3.11+) on the changed file and returns only the medium-or-worse findings
   > the edit introduced, so Claude fixes them in the same turn. An opt-in Stop gate and an install guard (denies
   > packages the local OSV index lists as malicious) are included.
   >
   > **Hooks.** Seven matcher entries (SessionStart, PreToolUse on file tools and on Bash, PostToolUse on file tools and on Bash, PostToolUseFailure on Bash, Stop), all `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/kestrix_hook.py" <event>`: one 917-line
   > standard-library script. It runs only the `kestrix-scan` on PATH (never one in the project), never a shell or
   > an installer, and fails open (exit 0, no output) on any error.
   >
   > **Network: none from hooks.** `tests/test_no_network.py` runs every hook with sockets refused in the hook and in
   > the scanner it starts. The only network command is the user-run `kestrix-scan db update` (OSV data).
   >
   > **Data:** session snapshots in `${CLAUDE_PLUGIN_DATA}`, deleted after 14 days. No telemetry, no credentials.
   > Latency: a non-install Bash command costs about 60 ms (Python start-up); a post-edit scan about 95 ms on a
   > 100-line file. License Apache-2.0.

   Their `CLAUDE.md` asks for things the skills do not yet have: "When to Use" and "When NOT to Use" sections in
   every SKILL.md, "Rationalizations to Reject" in security skills, and SKILL.md under 500 lines
   (`fixing-security-findings` is 1,466 lines, generated). It also prefers shell plus `jq` over Python for
   PreToolUse hooks on Bash. These matter for route 3; mention them in route 2 if asked.

## Positioning

**Pitch.** Kestrix is an offline, deterministic security layer for the code Claude writes. After every edit, a hook
runs the local `kestrix-scan` scanner and hands Claude only the findings that edit introduced, each with a CWE and a
concrete fix, and asks Claude to repair them before moving on. It needs no account and sends nothing anywhere: the hooks open
no network connections, which a test checks. Its 60 rules (Python, JavaScript and TypeScript, hard-coded secrets,
Claude Code and MCP configuration, dependency lockfiles) are Apache-2.0, so you can read, audit and ship them. It is
designed to run alongside Anthropic's model-based `security-guidance` plugin and `/security-review`, not to replace
them: rules miss things a model can reason about, and a clean scan means no rule fired, not that the code is secure.

| | Kestrix plugin | Anthropic `security-guidance` |
| --- | --- | --- |
| Check on Edit/Write | Rules over the parsed code (Python syntax tree and data flow; JS/TS tokens), only findings the edit introduced | Regex checks on about 25 patterns |
| Check at Stop | Opt-in gate on new high/critical findings, at most 3 blocks | LLM review of the diff |
| Where code goes | Nowhere; hooks open no sockets (`tests/test_no_network.py`) | Diffs and files go to the model endpoint |
| Account | None | Claude account (already in use) |
| Same input, same result | Yes, rule-based | Model review can vary between runs |
| Install guard (known-malicious packages) | Yes, from a local OSV index | Not part of the plugin |
| Rules license | Apache-2.0, redistributable | See its repository |
| BenchmarkPython v0.1 score (TPR − FPR) | 39.5, **not blind**: rules were changed after an earlier run's gap analysis | 1.6 (regex layer only) |

Sources: the security-guidance column comes from [the competitive landscape](research/competitive-landscape-2026-10.md),
which cites [the plugin](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/security-guidance).
The benchmark row comes from [the scorecard](benchmarks/benchmarkpython.md) (2026-10-20, security-guidance 2.0.14);
read its [disclosure](benchmarks/benchmarkpython.md#disclosure-this-round-of-rule-changes-was-informed-by-the-benchmark)
before quoting it. BenchmarkPython is synthetic and measures category coverage, not real-world detection rates, and
it compares only the security-guidance regex layer, not its model review. Kestrix's blind result on the same suite
was 15.8. Do not describe Kestrix as more accurate than a model review: no such measurement exists.
