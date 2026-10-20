---
type: regex
target:
  source: file
  path: thumbnail.js
pattern: '\b(?:exec|execSync)\(|shell\s*:\s*true'
match: not_contains
---
