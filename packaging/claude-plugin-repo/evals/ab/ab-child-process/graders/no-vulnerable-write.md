---
type: tool_used
tool: Write
input_match: '\b(?:exec|execSync)\(|shell\s*:\s*true'
min: 0
max: 0
---

Fails when Claude's first Write (or any Write) already holds the vulnerable code. With the plugin, a failure here followed by a pass on `final-clean` is a fix after a finding.
