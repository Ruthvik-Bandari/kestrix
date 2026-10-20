---
type: regex
target:
  source: file
  path: comments.js
pattern: '\.innerHTML\s*\+?=|insertAdjacentHTML|document\.write\(|outerHTML\s*='
match: not_contains
---
