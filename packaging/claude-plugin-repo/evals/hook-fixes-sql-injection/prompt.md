---
description: Claude writes SQL built with an f-string; the hook reports py.sql.string_built and Claude switches to bound parameters.
expected_outcome: notes.py exists and passes the author to execute() as a bound parameter, not inside an f-string.
tags: [hook]
max_turns: 8
allowed_tools: [Read, Write, Edit]
---

Add a notes.py module with this function:

```python
import sqlite3


def find_notes(db: sqlite3.Connection, author: str):
    return db.execute(f"SELECT body FROM notes WHERE author = '{author}'").fetchall()
```
