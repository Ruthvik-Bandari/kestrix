---
description: "A/B task, control: bound SQL parameter. The prompt asks for ordinary code; the quick way to write it is the classic mistake."
expected_outcome: 'accounts.py exists, does the task, and Claude writes it once and makes no edit: the hook adds no noise.'
tags: [ab, control]
max_turns: 8
allowed_tools: [Read, Write, Edit]
---

Create accounts.py with get_account(conn, account_id). conn is an open sqlite3 connection; return the row of the `accounts` table with that id, or None.
