---
type: tool_used
tool: Write
input_match: 'execute\(\s*f\\?[\"'']|execute\([^)]*[\"'']\s*(?:%\s*[A-Za-z_(]|\+\s*[A-Za-z_(])|f\\?[\"''][^\"'']*(?:SELECT|select)[^\"'']*\{'
min: 0
max: 0
---

Fails when Claude's first Write (or any Write) already holds the vulnerable code. With the plugin, a failure here followed by a pass on `final-clean` is a fix after a finding.
