// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { Link } from "react-router";
import { dashboardPath } from "../../app/paths";
import { toolFor, type ToolPage } from "../../app/tools";
import { Icon } from "../../components/Icon";
import { PageHeader } from "../../components/ui";
import { useTitle } from "../../lib/useTitle";

/** A tool page's header: its name, its one-line summary and the way to the full docs. */
export function ToolHeader({ page, aside }: { page: ToolPage; aside?: ReactNode }) {
  const tool = toolFor(page);
  useTitle(tool.name);
  return (
    <PageHeader
      title={tool.name}
      lede={
        <>
          {tool.summary}{" "}
          <Link to={dashboardPath(`docs/${page}`)} className="link inline-flex items-center gap-1 font-medium whitespace-nowrap">
            Read the docs
            <Icon name="arrowRight" size={14} />
          </Link>
        </>
      }
      aside={aside}
    />
  );
}
