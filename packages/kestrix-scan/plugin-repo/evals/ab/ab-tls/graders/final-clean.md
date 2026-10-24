---
type: regex
target:
  source: file
  path: report_client.py
pattern: 'verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False'
match: not_contains
---
