---
description: Claude writes code with no medium-or-worse finding; the hook must add nothing.
expected_outcome: slug.py exists and the transcript holds no Kestrix finding.
tags: [hook, noise]
max_turns: 6
allowed_tools: [Read, Write, Edit]
---

Create slug.py with a function slugify(title: str) -> str that lowercases the title, replaces each run of
characters other than a-z and 0-9 with a single hyphen, and strips hyphens from both ends. Use only the
standard library.
