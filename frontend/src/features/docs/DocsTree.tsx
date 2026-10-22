// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId, useState } from "react";
import { Link } from "react-router";
import { Icon } from "../../components/Icon";
import { cx } from "../../components/ui";
import { ancestorPaths, docTree, pageAt } from "./content";
import type { TreeNode } from "./model";
import { useDocPath } from "./scope";

/** The paths that must be open to show the current page: its ancestors, and itself when it has pages under it. */
function openFor(current: string): string[] {
  const own = docTree.flatMap((group) => collect(group.nodes)).find((node) => node.path === current);
  return [...ancestorPaths(current), ...(own?.children ? [own.path] : [])];
}

function collect(nodes: TreeNode[]): TreeNode[] {
  return nodes.flatMap((node) => [node, ...(node.children ? collect(node.children) : [])]);
}

function Row({
  node,
  current,
  open,
  onToggle,
  onNavigate,
  depth,
}: {
  node: TreeNode;
  current: string;
  open: Set<string>;
  onToggle: (path: string) => void;
  onNavigate: (() => void) | undefined;
  depth: number;
}) {
  const docPath = useDocPath();
  const listId = useId();
  const page = pageAt(node.path);
  if (!page) return null;
  const isCurrent = node.path === current;
  const isAncestor = ancestorPaths(current).includes(node.path);
  const expanded = open.has(node.path);
  return (
    <li>
      <div className="flex items-center gap-0.5">
        <Link
          to={docPath(node.path)}
          aria-current={isCurrent ? "page" : undefined}
          onClick={onNavigate}
          className={cx(
            "flex min-h-9 min-w-0 flex-1 items-center rounded-lg px-2.5 text-[0.875rem] leading-snug transition-colors duration-150 motion-reduce:transition-none",
            isCurrent
              ? "bg-accent-soft font-medium text-accent-text"
              : isAncestor
                ? "font-medium text-ink hover:bg-inset"
                : "text-ink-2 hover:bg-inset hover:text-ink",
          )}
        >
          {page.nav}
        </Link>
        {node.children ? (
          <button
            type="button"
            aria-expanded={expanded}
            aria-controls={listId}
            aria-label={`${page.nav}: ${expanded ? "collapse" : "expand"} pages`}
            onClick={() => {
              onToggle(node.path);
            }}
            className="flex size-9 flex-none items-center justify-center rounded-lg text-ink-3 hover:bg-inset hover:text-ink"
          >
            <Icon name="chevronRight" size={16} className={cx("transition-transform duration-150 motion-reduce:transition-none", expanded && "rotate-90")} />
          </button>
        ) : null}
      </div>
      {node.children ? (
        <ul id={listId} hidden={!expanded} className={cx("ml-3 border-l border-line pl-2", depth > 0 && "ml-2")}>
          {node.children.map((child) => (
            <Row key={child.path} node={child} current={current} open={open} onToggle={onToggle} onNavigate={onNavigate} depth={depth + 1} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

/**
 * The documentation tree: sections, pages and the pages under them. A navigation landmark; the page you are
 * on has aria-current="page" and its parents are open; each page that has pages under it has a disclosure
 * button (aria-expanded) beside its link.
 */
export function DocsTree({ current, onNavigate }: { current: string; onNavigate?: () => void }) {
  const docPath = useDocPath();
  const [open, setOpen] = useState<Set<string>>(() => new Set(openFor(current)));
  const [seen, setSeen] = useState(current);
  // Following a link (or the browser's back button) opens the path to the new page; what you collapsed stays collapsed.
  if (seen !== current) {
    setSeen(current);
    setOpen((previous) => new Set([...previous, ...openFor(current)]));
  }
  const toggle = (path: string) => {
    setOpen((previous) => {
      const next = new Set(previous);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };
  const groupId = useId();
  return (
    <nav aria-label="Documentation" className="min-h-0 overflow-y-auto overscroll-contain pr-1 pb-6">
      <Link
        to={docPath("")}
        aria-current={current === "" ? "page" : undefined}
        onClick={onNavigate}
        className={cx(
          "flex min-h-9 items-center gap-2 rounded-lg px-2.5 text-[0.875rem] font-medium transition-colors duration-150 motion-reduce:transition-none",
          current === "" ? "bg-accent-soft text-accent-text" : "text-ink hover:bg-inset",
        )}
      >
        <Icon name="bookOpen" size={16} className="flex-none" />
        Documentation home
      </Link>
      <ul className="mt-4 space-y-5">
        {docTree.map((group, index) => (
          <li key={group.title}>
            <p id={`${groupId}-${index}`} className="mb-1 px-2.5 text-[0.75rem] font-semibold tracking-[0.08em] text-ink-3 uppercase">
              {group.title}
            </p>
            <ul aria-labelledby={`${groupId}-${index}`}>
              {group.nodes.map((node) => (
                <Row key={node.path} node={node} current={current} open={open} onToggle={toggle} onNavigate={onNavigate} depth={0} />
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </nav>
  );
}
