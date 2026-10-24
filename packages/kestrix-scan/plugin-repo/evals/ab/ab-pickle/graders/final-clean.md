---
type: regex
target:
  source: file
  path: cache.py
pattern: 'pickle\.loads?\(|marshal\.loads?\(|shelve\.open|dill\.'
match: not_contains
---
