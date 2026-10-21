// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { lazy, Suspense, type ComponentType, type ReactNode } from "react";
import { createBrowserRouter, Navigate, useLocation, type RouteObject } from "react-router";
import { isHosted } from "../lib/mode";
import { RequireSignIn } from "./RequireSignIn";
import { Layout } from "./Layout";
import { dashboardPath, landingPath, PRIVACY_PATH, SIGNIN_PATH, TERMS_PATH } from "./paths";
import { RouteError } from "./RouteError";

// One chunk per page; the shell (layout, API client, tokens) loads once.
const Home = lazy(() => import("../features/home/HomePage"));
const Detect = lazy(() => import("../features/detect/DetectPage"));
const Webcheck = lazy(() => import("../features/webcheck/WebcheckPage"));
const Forensics = lazy(() => import("../features/forensics/ForensicsPage"));
const Mail = lazy(() => import("../features/mail/MailPage"));
const Bitcoin = lazy(() => import("../features/bitcoin/BitcoinPage"));
const Migration = lazy(() => import("../features/bitcoin/MigrationPage"));
const Settings = lazy(() => import("../features/settings/SettingsPage"));
const History = lazy(() => import("../features/history/HistoryPage"));
const HistoryDetail = lazy(() => import("../features/history/HistoryDetailPage"));
const Docs = lazy(() => import("../features/docs/DocsPage"));
const Guide = lazy(() => import("../features/guides/GuidePage").then((m) => ({ default: m.GuidePage })));
const NotFound = lazy(() => import("./NotFound"));
const Landing = lazy(() => import("../features/landing/LandingPage"));
const SignIn = lazy(() => import("../features/auth/SignInPage"));
const Privacy = lazy(() => import("../features/legal/PrivacyPage"));
const Terms = lazy(() => import("../features/legal/TermsPage"));
const PublicNotFound = lazy(() => import("../features/legal/PublicNotFound"));

function page(Component: ComponentType): ReactNode {
  return (
    <Suspense fallback={null}>
      <Component />
    </Suspense>
  );
}

/** Hosted: sign-in failures land on /welcome?signin=failed; the landing page lives at "/". */
function WelcomeRedirect() {
  const { search } = useLocation();
  return <Navigate to={`${landingPath()}${search}`} replace />;
}

/** Pages with their own chrome (no sidebar). */
function publicRoutes(): RouteObject[] {
  return [
    // The public landing page has its own chrome (no sidebar); its path is one constant.
    { path: landingPath(), ErrorBoundary: RouteError, element: page(Landing) },
    { path: PRIVACY_PATH, ErrorBoundary: RouteError, element: page(Privacy) },
    { path: TERMS_PATH, ErrorBoundary: RouteError, element: page(Terms) },
  ];
}

/** Dashboard pages served in both modes. */
const shared: RouteObject[] = [
  { path: "code", element: <Guide tool="code" /> },
  { path: "claude-plugin", element: <Guide tool="claude-plugin" /> },
  { path: "docs", Component: Docs },
  { path: "docs/:slug", Component: Docs },
  { path: "history", Component: History },
  { path: "history/:id", Component: HistoryDetail },
  { path: "settings", Component: Settings },
];

/** The routes for the mode set at start-up (lib/mode.ts); call after `setMode`. */
export function createRoutes(): RouteObject[] {
  if (isHosted()) {
    // Live pages only for the modules the hosted service serves; the local-only tools get guides.
    return [
      ...publicRoutes(),
      { path: "/welcome", element: <WelcomeRedirect /> },
      { path: SIGNIN_PATH, ErrorBoundary: RouteError, element: page(SignIn) },
      {
        path: dashboardPath(),
        ErrorBoundary: RouteError,
        element: (
          <RequireSignIn>
            <Layout />
          </RequireSignIn>
        ),
        children: [
          { index: true, Component: Home },
          { path: "webcheck", Component: Webcheck },
          { path: "forensics", Component: Forensics },
          { path: "mail", Component: Mail },
          // Local-only tools: a guide to running them on your own computer, no live controls.
          { path: "detect", element: <Guide tool="detect" /> },
          { path: "bitcoin", element: <Guide tool="bitcoin" /> },
          ...shared,
          { path: "*", Component: NotFound },
        ],
      },
      { path: "*", ErrorBoundary: RouteError, element: page(PublicNotFound) },
    ];
  }
  return [
    ...publicRoutes(),
    {
      path: dashboardPath(),
      Component: Layout,
      ErrorBoundary: RouteError,
      children: [
        { index: true, Component: Home },
        { path: "detect", Component: Detect },
        { path: "webcheck", Component: Webcheck },
        { path: "forensics", Component: Forensics },
        { path: "mail", Component: Mail },
        { path: "bitcoin", Component: Bitcoin },
        { path: "bitcoin/migration/:addressType", Component: Migration },
        ...shared,
        { path: "*", Component: NotFound },
      ],
    },
  ];
}

export function createAppRouter() {
  return createBrowserRouter(createRoutes());
}
