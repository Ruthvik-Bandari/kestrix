---
type: regex
target:
  source: file
  path: settings.py
pattern: 'yaml\.(?:load|unsafe_load)\((?![^)]*Safe)|FullLoader|UnsafeLoader'
match: not_contains
---
