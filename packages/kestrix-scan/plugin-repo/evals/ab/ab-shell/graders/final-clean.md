---
type: regex
target:
  source: file
  path: archive.py
pattern: 'shell\s*=\s*True|os\.(?:system|popen)\('
match: not_contains
---
