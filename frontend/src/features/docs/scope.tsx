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
    grid: "lg:grid-cols-[15rem_minmax(0,1fr)] xl:grid-cols-[15rem_minmax(0,1fr)_11rem] lg:gap-x-10",
    tree: "hidden lg:block",
    treeSticky: "lg:sticky lg:top-24 lg:max-h-[calc(100dvh-7rem)]",
    toc: "xl:block",
    tocSticky: "xl:top-24",
    bar: "lg:hidden",
    tocMenu: "xl:hidden",
    scrollMargin: "scroll-mt-24",
    treeQuery: "(min-width: 1024px)",
  },
  app: {
    grid: "min-[1280px]:grid-cols-[14rem_minmax(0,1fr)] min-[1400px]:grid-cols-[14rem_minmax(0,1fr)_11rem] min-[1280px]:gap-x-8",
    tree: "hidden min-[1280px]:block",
    treeSticky: "min-[1280px]:sticky min-[1280px]:top-8 min-[1280px]:max-h-[calc(100dvh-4rem)]",
    toc: "min-[1400px]:block",
    tocSticky: "min-[1400px]:top-8",
    bar: "min-[1280px]:hidden",
    tocMenu: "min-[1400px]:hidden",
    scrollMargin: "scroll-mt-6",
    treeQuery: "(min-width: 1280px)",
  },
};
