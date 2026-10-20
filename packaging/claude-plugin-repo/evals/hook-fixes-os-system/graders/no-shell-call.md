---
type: regex
target:
  source: file
  path: export.py
pattern: 'os\.system|shell\s*=\s*True'
match: not_contains
---
