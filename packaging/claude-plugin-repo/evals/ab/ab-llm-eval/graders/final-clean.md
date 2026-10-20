---
type: regex
target:
  source: file
  path: calc.py
pattern: '(?<![\w.])(?:eval|exec)\('
match: not_contains
---
