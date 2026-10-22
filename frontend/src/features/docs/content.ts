// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { pages, section } from "./blocks";
import { LEGACY_DOC_PATHS, type DocPage, type PageMeta, type TreeNode, type TreeSection } from "./model";
import { bitcoinPages } from "./pages/bitcoin";
import { detectPages } from "./pages/detect";
import { emailPages } from "./pages/email";
import { forensicsPages } from "./pages/forensics";
import { gettingStartedPages } from "./pages/getting-started";
import { guidePages } from "./pages/guides";
import { pluginPages } from "./pages/plugin";
import { referencePages } from "./pages/reference";
import { securityPages } from "./pages/security";
import { scannerPages } from "./pages/scanner";
import { websitePages } from "./pages/website";

/*
 * The documentation: typed pages (./pages/*), one navigation tree, and the lookups the sidebar, the
 * breadcrumbs, previous/next, search and the redirects all read. It summarizes README.md,
 * docs/modules/*.md, docs/hosted.md, docs/security-model.md, docs/claude-plugin.md,
 * docs/benchmarks/cvefixes.md, docs/research/{mail,linkfile}-benchmark.md and
 * packages/kestrix-scan/README.md, and must never contradict them: when those change, change the page in the
 * same commit. Each tool's overview is built from app/tools.ts and features/tools/content.ts, so nothing
 * about a tool is written twice.
 */

/** A tool-style node: its overview page with the four topic pages under it. */
function toolNode(base: string): TreeNode {
  return {
    path: base,
    children: ["how-it-works", "using-it", "findings", "limits"].map((leaf) => ({ path: `${base}/${leaf}` })),
  };
}

/** The navigation tree: sections, pages and the pages nested under them. The home page sits above it. */
export const docTree: TreeSection[] = [
  {
    title: "Getting started",
    nodes: [
      "getting-started/what-is-kestrix",
      "getting-started/quickstart",
      "getting-started/installation",
      "getting-started/run-locally",
      "getting-started/hosted-service",
      "getting-started/troubleshooting",
    ].map((path) => ({ path })),
  },
  {
    title: "Tools",
    nodes: ["tools/email", "tools/website", "tools/forensics", "tools/detection-repair", "tools/bitcoin"].map(toolNode),
  },
  {
    title: "Code security",
    nodes: [
      {
        path: "code-security/kestrix-scan",
        children: ["install-and-cli", "configuration", "ci-and-pre-commit"].map((leaf) => ({ path: `code-security/kestrix-scan/${leaf}` })),
      },
      { path: "code-security/rules" },
      {
        path: "code-security/claude-plugin",
        children: ["install", "hooks", "commands-and-skills", "verified-behaviour"].map((leaf) => ({ path: `code-security/claude-plugin/${leaf}` })),
      },
      { path: "code-security/accuracy" },
    ],
  },
  {
    title: "Security and trust",
    nodes: ["security/reporting", "security/threat-model", "security/data-handling", "security/authorized-use", "security/supply-chain"].map((path) => ({ path })),
  },
  {
    title: "Reference",
    nodes: ["reference/architecture", "reference/cli", "reference/http-api", "reference/configuration", "reference/licenses", "reference/whats-new"].map((path) => ({ path })),
  },
];

const home: DocPage = {
  path: "",
  title: "Kestrix documentation",
  nav: "Documentation",
  summary: "Security checks for your code, and a local-first security workbench. Everything runs on your own machine unless you ask otherwise.",
  sections: docTree.map((group) => section(group.title, pages(...group.nodes.map((node) => node.path)))),
};

export const docPages: DocPage[] = [
  home,
  ...gettingStartedPages,
  ...guidePages,
  ...emailPages,
  ...websitePages,
  ...forensicsPages,
  ...detectPages,
  ...bitcoinPages,
  ...scannerPages,
  ...pluginPages,
  ...securityPages,
  ...referencePages,
];

/*
 * Each page has one job (Diataxis): a tutorial you follow, a how-to you do, a reference you look things up in,
 * or an explanation you read to understand. `source` names the repository files the page summarizes, so a
 * change there is a change here.
 */
const SOURCES: Record<string, string[]> = {
  "getting-started/what-is-kestrix": ["README.md"],
  "getting-started/quickstart": ["README.md", "docs/modules/mail.md", "docs/modules/code.md"],
  "getting-started/installation": ["README.md", "docs/release.md"],
  "getting-started/run-locally": ["README.md", "docs/api.md"],
  "getting-started/hosted-service": ["docs/hosted.md"],
  "getting-started/troubleshooting": ["docs/modules/*.md", "docs/claude-plugin.md"],
  "tools/email": ["docs/modules/mail.md"],
  "tools/website": ["docs/modules/webcheck.md"],
  "tools/forensics": ["docs/modules/forensics.md", "docs/research/linkfile-benchmark.md"],
  "tools/detection-repair": ["docs/modules/detect.md"],
  "tools/bitcoin": ["docs/modules/bitcoin.md"],
  "code-security/kestrix-scan": ["docs/modules/code.md", "packages/kestrix-scan/README.md"],
  "code-security/rules": ["kestrix-scan rules", "docs/modules/code-rules-provenance.md"],
  "code-security/claude-plugin": ["docs/claude-plugin.md", "docs/claude-skill.md", "docs/benchmarks/plugin-ab.md"],
  "code-security/accuracy": ["docs/benchmarks/cvefixes.md"],
  "security/reporting": ["SECURITY.md"],
  "security/threat-model": ["docs/security-model.md"],
  "security/data-handling": ["docs/security-model.md", "docs/hosted.md", "docs/modules/*.md"],
  "security/authorized-use": ["docs/modules/webcheck.md", "docs/hosted.md"],
  "security/supply-chain": ["docs/release.md", "NOTICE", ".github/workflows/release.yml"],
  "reference/architecture": ["README.md", "docs/security-model.md", "docs/hosted.md"],
  "reference/cli": ["kestrix --help"],
  "reference/http-api": ["docs/api.md"],
  "reference/configuration": ["docs/security-model.md", "docs/modules/code.md"],
  "reference/licenses": ["NOTICE", "docs/research/dataset-licenses.md"],
  "reference/whats-new": ["CHANGELOG.md"],
};

const TYPES: Record<string, PageMeta["type"]> = {
  "getting-started/quickstart": "tutorial",
  "getting-started/installation": "how-to",
  "getting-started/run-locally": "how-to",
  "getting-started/troubleshooting": "how-to",
  "security/reporting": "how-to",
  "code-security/rules": "reference",
  "reference/architecture": "reference",
  "reference/cli": "reference",
  "reference/http-api": "reference",
  "reference/configuration": "reference",
  "reference/licenses": "reference",
  "reference/whats-new": "reference",
};

/** The reference tables of a tool and the how-to pages are named by their last path segment. */
function typeOf(path: string): PageMeta["type"] {
  const exact = TYPES[path];
  if (exact) return exact;
  const leaf = path.split("/").pop();
  if (leaf === "using-it" || leaf === "install-and-cli" || leaf === "configuration" || leaf === "ci-and-pre-commit" || leaf === "install") return "how-to";
  if (leaf === "findings" || leaf === "commands-and-skills") return "reference";
  return "explanation";
}

/** The date the content was last checked against the repository docs it summarizes. Update it with the content. */
export const DOCS_REVIEWED = "2026-10-22";

export function metaOf(path: string): PageMeta {
  const root = path.split("/").slice(0, 2).join("/");
  return { type: typeOf(path), source: SOURCES[path] ?? SOURCES[root] ?? ["README.md"], reviewed: DOCS_REVIEWED };
}

const byPath = new Map(docPages.map((page) => [page.path, page]));

export function pageAt(path: string): DocPage | undefined {
  return byPath.get(path);
}

function walk(nodes: TreeNode[], visit: (node: TreeNode, ancestors: TreeNode[]) => void, ancestors: TreeNode[] = []): void {
  for (const node of nodes) {
    visit(node, ancestors);
    if (node.children) walk(node.children, visit, [...ancestors, node]);
  }
}

/** Every page in reading order: the home page, then the tree top to bottom. Previous and next follow it. */
export const readingOrder: DocPage[] = (() => {
  const order: DocPage[] = [home];
  for (const group of docTree) {
    walk(group.nodes, (node) => {
      const page = byPath.get(node.path);
      if (page) order.push(page);
    });
  }
  return order;
})();

const trail = new Map<string, { section: TreeSection; ancestors: TreeNode[] }>();
for (const group of docTree) walk(group.nodes, (node, ancestors) => trail.set(node.path, { section: group, ancestors }));

/** The tree section a page belongs to (null for the home page). */
export function sectionOf(path: string): TreeSection | null {
  return trail.get(path)?.section ?? null;
}

/** The nodes above a page in the tree, outermost first (not including the page itself). */
export function ancestorPaths(path: string): string[] {
  return trail.get(path)?.ancestors.map((node) => node.path) ?? [];
}

export interface Crumb {
  label: string;
  /** Absent for the section label, which has no page of its own. */
  path?: string;
}

/** Docs › Section › parent pages › this page. */
export function breadcrumbs(path: string): Crumb[] {
  const page = byPath.get(path);
  if (!page || path === "") return [];
  const found = trail.get(path);
  const crumbs: Crumb[] = [{ label: "Docs", path: "" }];
  if (found) {
    crumbs.push({ label: found.section.title });
    for (const ancestor of found.ancestors) crumbs.push({ label: byPath.get(ancestor.path)?.nav ?? ancestor.path, path: ancestor.path });
  }
  crumbs.push({ label: page.nav });
  return crumbs;
}

export type Resolved = { kind: "page"; page: DocPage } | { kind: "redirect"; to: string } | { kind: "missing" };

/** What the part of the address after "/docs/" shows: a page, a redirect from an old flat address, or nothing. */
export function resolveDoc(rest: string | undefined): Resolved {
  const path = (rest ?? "").replace(/^\/+|\/+$/g, "");
  const page = byPath.get(path);
  if (page) return { kind: "page", page };
  const legacy = LEGACY_DOC_PATHS[path];
  if (legacy !== undefined) return { kind: "redirect", to: legacy };
  return { kind: "missing" };
}
