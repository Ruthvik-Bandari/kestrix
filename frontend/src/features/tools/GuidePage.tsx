// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ToolPage } from "../../app/tools";
import { Badge } from "../../components/ui";
import { ToolGuide } from "./ToolGuide";
import { ToolHeader } from "./ToolHeader";

/** A tool that runs on the user's own computer: a guide only, with no live controls. */
export function GuidePage({ tool }: { tool: ToolPage }) {
  return (
    <>
      <ToolHeader
        page={tool}
        aside={
          <Badge tone="accent" icon="terminal">
            Run locally
          </Badge>
        }
      />
      <ToolGuide tool={tool} />
    </>
  );
}
