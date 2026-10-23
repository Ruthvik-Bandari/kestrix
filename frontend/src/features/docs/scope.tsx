// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { createContext, useContext } from "react";
import { dashboardPath, docsPath } from "../../app/paths";

/** Where these docs are mounted: the app shell (links stay in the app) or the public shell (links stay public). */
export type Scope = "app" | "public";

export const DocsScope = createContext<Scope>("app");

export function useScope(): Scope {
  return useContext(DocsScope);
}

/** A docs page path ("tools/email", or "" for the home page) as an address in the current mount. */
export function useDocPath(): (path: string) => string {
  const scope = useScope();
  return (path) => (scope === "public" ? docsPath(path) : dashboardPath(path ? `docs/${path}` : "docs"));
}

/*
 * The breakpoints differ by mount, because the app shell already spends 14rem on its own rail: in the public
 * shell the docs tree is a column from 1024px and "On this page" from 1280px; in the app shell the tree is
 * a column from 1280px and "On this page" from 1400px. Below those, the tree is a drawer and "On this page"
 * is a menu above the article. Class names are written out in full so Tailwind finds them.
 */
export interface Layout {
  grid: string;
  tree: string;
  treeSticky: string;
  toc: string;
  tocSticky: string;
  /** Hidden from the tree breakpoint up: the bar with the drawer and search buttons. */
  bar: string;
  /** Hidden from the "On this page" breakpoint up: the inline menu. */
  tocMenu: string;
  scrollMargin: string;
  /** Whether the tree column is showing right now (for the "/" shortcut). */
  treeQuery: string;
}

export const LAYOUTS: Record<Scope, Layout> = {
  public: {
    grid: "@min-[60rem]:grid-cols-[15rem_minmax(0,1fr)] @min-[76rem]:grid-cols-[15rem_minmax(0,1fr)_11rem] @min-[60rem]:gap-x-10",
    tree: "hidden @min-[60rem]:block",
    treeSticky: "@min-[60rem]:sticky @min-[60rem]:top-24 @min-[60rem]:max-h-[calc(100dvh-7rem)]",
    toc: "@min-[76rem]:block",
    tocSticky: "@min-[76rem]:top-24",
    bar: "@min-[60rem]:hidden",
    tocMenu: "@min-[76rem]:hidden",
    scrollMargin: "scroll-mt-24",
    treeQuery: "(min-width: 1024px)",
  },
  app: {
    grid: "@min-[60rem]:grid-cols-[14rem_minmax(0,1fr)] @min-[68rem]:grid-cols-[14rem_minmax(0,1fr)_11rem] @min-[60rem]:gap-x-8",
    tree: "hidden @min-[60rem]:block",
    treeSticky: "@min-[60rem]:sticky @min-[60rem]:top-8 @min-[60rem]:max-h-[calc(100dvh-4rem)]",
    toc: "@min-[68rem]:block",
    tocSticky: "@min-[68rem]:top-8",
    bar: "@min-[60rem]:hidden",
    tocMenu: "@min-[68rem]:hidden",
    scrollMargin: "scroll-mt-6",
    treeQuery: "(min-width: 1280px)",
  },
};
