---
name: "Scanner rule: false positive or missed finding"
about: A kestrix-scan rule flags safe code, or misses insecure code it should catch
title: "<rule id>: false positive / missed finding"
labels: scanner-rule
---

<!--
Do not paste private or proprietary code, or real secrets. Reduce the case to a minimal snippet you wrote
yourself, or link a public commit or advisory. Replace any credential with a placeholder.
A vulnerability in Kestrix itself (not a rule result) goes through SECURITY.md, not an issue.
-->

**Kind:** false positive (safe code flagged) / missed finding (insecure code not flagged)

**Rule id:** for example `py.subprocess.shell_true` (from the report, or `kestrix-scan rules`; leave empty for a miss with no rule)

**Minimal snippet** (the smallest file that shows it; name the file so the language is clear)

```text
```

**Expected:** what the scanner should report, or why this code is safe

**Actual:** the finding as printed (`kestrix-scan <file>`), or "no finding"

**Source, for a missed finding:** a link to the public fix commit or advisory, if there is one

**Version:** `kestrix-scan --version`
