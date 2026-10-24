---
description: A security review request triggers the secure-code-review skill, and the reply names the command injection.
expected_outcome: Claude invokes kestrix:secure-code-review and reports the shell=True command injection (CWE-78).
tags: [skill]
max_turns: 8
allowed_tools: [Read, Glob, Grep, Skill]
---

Can you do a security review of this function before I merge it? List the problems by severity.

```python
import subprocess


def archive(folder):
    subprocess.run(f"tar czf notes.tgz {folder}", shell=True, check=True)
```
