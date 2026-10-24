---
type: regex
target:
  source: file
  path: users.py
pattern: 'execute\(\s*f\\?[\"'']|execute\([^)]*[\"'']\s*(?:%\s*[A-Za-z_(]|\+\s*[A-Za-z_(])|f\\?[\"''][^\"'']*(?:SELECT|select)[^\"'']*\{'
match: not_contains
---
