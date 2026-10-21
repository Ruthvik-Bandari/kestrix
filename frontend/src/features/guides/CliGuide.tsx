// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Icon } from "../../components/Icon";
import { Disclosure } from "../../components/ui";
import type { GuideTool } from "./guides";
import { ToolGuide } from "./ToolGuide";

/** The same guide, collapsed, under a tool that runs in the local dashboard. */
export function CliGuide({ tool }: { tool: GuideTool }) {
  return (
    <div className="mt-12">
      <Disclosure
        summary={
          <span className="inline-flex items-center gap-2">
            <Icon name="terminal" size={16} className="text-accent-text" />
            How to use it from the command line
          </span>
        }
      >
        <ToolGuide tool={tool} compact />
      </Disclosure>
    </div>
  );
}
