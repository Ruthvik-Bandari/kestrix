# Recording the plugin demo

How to capture the screenshots and the recording for the plugin's directory listing and README. The demo itself
is [`docs/demo/`](README.md). Record on a machine with no real credentials in the shell history or
the terminal scrollback, and in a fresh directory, so nothing private appears on screen.

## 1. Prepare a clean environment

```bash
uv tool install kestrix-scan                       # or: pipx install kestrix-scan
claude plugin marketplace add Ruthvik-Bandari/kestrix-claude-plugin
claude plugin install kestrix@kestrix
python3 docs/demo/setup_demo.py ~/kestrix-demo     # fake token assembled at run time
cd ~/kestrix-demo
```

Before the plugin repository is public, install from the generated copy instead:
`uv run python scripts/build_plugin_repo.py`, then `claude plugin marketplace add ./dist/claude-plugin-repo`.

Check the expected output first, so the recording shows what the docs promise:

```bash
uv run python scripts/build_demo_expected.py --check   # from the Kestrix checkout; exit 0 means up to date
```

Terminal settings: about 110 by 32 characters, a font size of 16 or more, a plain prompt (`PS1='$ '`), and a
light or dark theme with good contrast. Close other windows and turn off notifications.

## 2. Record the terminal

Use [asciinema](https://docs.asciinema.org/) for a text recording (small, copyable, no video encoding):

```bash
asciinema rec kestrix-demo.cast --idle-time-limit 2 --command claude
```

Inside the session, give the prompts of [`docs/demo/prompts.md`](prompts.md) in order: steps 1, 2 and 4.
Press Ctrl+O after step 2 to show the hook context in the transcript. Exit with `/exit`.

For a video instead, use the macOS screen recorder (Shift-Command-5, **Record Selected Portion**) on the terminal
window, or OBS on Linux and Windows. Keep it under 90 seconds; cut waiting time rather than speeding it up.

To turn the cast into a GIF for the README, use [agg](https://github.com/asciinema/agg):

```bash
agg --font-size 16 kestrix-demo.cast kestrix-demo.gif
```

## 3. Screenshots to capture

Save PNG files (the directory accepts PNG, JPEG, GIF and WebP; keep each under 5 MiB). Suggested set:

1. **`hook-catches.png`**: step 2 with the transcript expanded, showing the Kestrix context line and Claude's fix.
2. **`scan-summary.png`**: step 1, Claude's summary of `/kestrix:scan` with the five findings.
3. **`fix-clean.png`**: the end of step 4, with the final re-scan reporting no medium-or-worse findings.
4. **`stop-gate.png`** (optional): step 3, the `Kestrix Stop gate:` system message.
5. **`plugin-panel.png`**: the `/plugin` panel showing `kestrix` installed, with its skills and hooks.

Check each image before publishing: no real paths with a username you do not want shown, no tokens other than
the fake `ghp_…` prefix, and no other plugins' output.

## 4. Where the files go

- The directory listing reads its description from the plugin README and `plugin.json`; images in the README
  appear on the listing. Put the images in `docs/images/` of the plugin repository (not inside `hooks/` or
  `skills/`) and reference them only with Markdown image syntax in the README, as the pre-submission checklist
  requires.
- Do not commit the `.cast` or video files to the plugin repository. The directory holds a version for a
  reviewer when it contains a binary other than complete PNG, JPEG, GIF and WebP images (a video) or a text file
  over 256 KiB (a long cast). Attach the recording to the GitHub release instead.
