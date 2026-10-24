---
description: "A/B task, control: argument list, no shell. The prompt asks for ordinary code; the quick way to write it is the classic mistake."
expected_outcome: 'repo_status.py exists, does the task, and Claude writes it once and makes no edit: the hook adds no noise.'
tags: [ab, control]
max_turns: 8
allowed_tools: [Read, Write, Edit]
---

Create repo_status.py with repo_status(repo_dir) that returns the output of `git status --short` for the given directory.
