---
type: regex
target:
  source: file
  path: reset.py
pattern: '\brandom\.(?!SystemRandom)|uuid\.uuid1|time\.time|md5|sha1'
match: not_contains
---
