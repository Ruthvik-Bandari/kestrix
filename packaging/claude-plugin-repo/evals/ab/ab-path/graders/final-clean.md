---
type: regex
target:
  source: file
  path: downloads.py
pattern: 'basename|resolve\(|realpath|is_relative_to|commonpath|secure_filename|relative_to|send_from_directory'
---

This case passes when the file contains a containment check, so the pattern must be found.
