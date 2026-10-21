// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Badge, PageHeader } from "../../components/ui";
import { useTitle } from "../../lib/useTitle";
import { guides, type GuideTool } from "./guides";
import { ToolGuide } from "./ToolGuide";

/** A tool that runs on the user's own computer: a guide only, with no live controls. */
export function GuidePage({ tool }: { tool: GuideTool }) {
  const guide = guides[tool];
  useTitle(guide.name);
  return (
    <>
      <PageHeader
        title={guide.name}
        lede="This tool runs on your own computer, not on Kestrix's server. Here is how to install it and use it from the command line."
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
