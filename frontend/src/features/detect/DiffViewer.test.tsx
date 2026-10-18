// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DiffViewer, parseDiff } from "./DiffViewer";

const DIFF = `--- a/rule.yml
+++ b/rule.yml
@@ -8,4 +8,6 @@
 detection:
   selection:
     Image|contains: \\AppData\\Local\\Temp\\
-  condition: selection
+  cg_filter_1:
+    ParentImage: C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe
+  condition: selection and not cg_filter_1
`;

describe("diff viewer", () => {
  it("parses a unified diff with old and new line numbers", () => {
    const lines = parseDiff(DIFF);
    expect(lines.filter((l) => l.kind === "file")).toHaveLength(2);
    expect(lines.find((l) => l.kind === "hunk")?.text).toBe("@@ -8,4 +8,6 @@");
    const context = lines.filter((l) => l.kind === "context");
    expect(context.map((l) => [l.oldNo, l.newNo])).toEqual([
      [8, 8],
      [9, 9],
      [10, 10],
    ]);
    const removed = lines.filter((l) => l.kind === "del");
    expect(removed).toEqual([{ kind: "del", text: "  condition: selection", oldNo: 11, newNo: null }]);
    const added = lines.filter((l) => l.kind === "add");
    expect(added.map((l) => l.newNo)).toEqual([11, 12, 13]);
    expect(added[2]?.text).toBe("  condition: selection and not cg_filter_1");
  });

  it("renders added and removed lines with counts and spoken markers", () => {
    const { container } = render(<DiffViewer diff={DIFF} label="rule.yml" />);
    expect(screen.getByText("3 added")).toBeTruthy();
    expect(screen.getByText("1 removed")).toBeTruthy();
    expect(container.querySelectorAll('tr[data-kind="add"]')).toHaveLength(3);
    expect(container.querySelectorAll('tr[data-kind="del"]')).toHaveLength(1);
    expect(screen.getAllByText("Added:")).toHaveLength(3);
    expect(screen.getByText("Removed:")).toBeTruthy();
    expect(screen.getByRole("region", { name: "Changes to rule.yml" })).toBeTruthy();
  });

  it("renders file text as plain text, never as markup", () => {
    const { container } = render(<DiffViewer diff={"@@ -1 +1 @@\n-a\n+<img src=x onerror=alert(1)>\n"} label="x" />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeTruthy();
  });
});
