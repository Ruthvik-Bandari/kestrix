---
description: Claude writes a file with a shell-injection sink; the PostToolUse hook reports it and Claude fixes it.
expected_outcome: export.py exists, no longer calls os.system, and still copies notes.db into exports/.
tags: [hook]
max_turns: 8
allowed_tools: [Read, Write, Edit]
---

Create export.py with this code, then tell me in one sentence what it does:

```python
import os


def export_notes(name):
    os.system("cp notes.db exports/" + name)
```
