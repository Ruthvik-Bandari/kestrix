// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { lazy, Suspense } from "react";
import { createBrowserRouter } from "react-router";
import { Layout } from "./Layout";
import { DASHBOARD_PATH, LANDING_PATH } from "./paths";
import { RouteError } from "./RouteError";

// One chunk per page; the shell (layout, API client, tokens) loads once.
const Overview = lazy(() => import("../features/overview/OverviewPage"));
const Detect = lazy(() => import("../features/detect/DetectPage"));
const Webcheck = lazy(() => import("../features/webcheck/WebcheckPage"));
const Forensics = lazy(() => import("../features/forensics/ForensicsPage"));
const Mail = lazy(() => import("../features/mail/MailPage"));
const Bitcoin = lazy(() => import("../features/bitcoin/BitcoinPage"));
const Migration = lazy(() => import("../features/bitcoin/MigrationPage"));
const Settings = lazy(() => import("../features/settings/SettingsPage"));
const NotFound = lazy(() => import("./NotFound"));
const Landing = lazy(() => import("../features/landing/LandingPage"));

export const router = createBrowserRouter([
  // The public landing page has its own chrome (no sidebar); its path is one constant.
  {
    path: LANDING_PATH,
    ErrorBoundary: RouteError,
    element: (
      <Suspense fallback={null}>
        <Landing />
      </Suspense>
    ),
  },
  {
    path: DASHBOARD_PATH,
    Component: Layout,
    ErrorBoundary: RouteError,
    children: [
      { index: true, Component: Overview },
      { path: "detect", Component: Detect },
      { path: "webcheck", Component: Webcheck },
      { path: "forensics", Component: Forensics },
      { path: "mail", Component: Mail },
      { path: "bitcoin", Component: Bitcoin },
      { path: "bitcoin/migration/:addressType", Component: Migration },
      { path: "settings", Component: Settings },
      { path: "*", Component: NotFound },
    ],
  },
]);
