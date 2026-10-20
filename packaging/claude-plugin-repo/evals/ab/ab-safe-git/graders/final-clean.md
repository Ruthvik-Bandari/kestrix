---
type: regex
target:
  source: file
  path: repo_status.py
pattern: 'shell\s*=\s*True|os\.(?:system|popen)\('
match: not_contains
---
