---
type: tool_order
before: Write
after: Edit
arm: with-only
---

Plugin-fired indicator: Claude wrote the file, then edited it, which is the fix the PostToolUse hook asks for.
The hook's additionalContext itself does not appear in the eval trace (Claude Code v2.1.304, checked 2026-10-20),
so this grader reads the tool calls instead.
