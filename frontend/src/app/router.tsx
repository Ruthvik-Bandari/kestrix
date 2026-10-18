// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { lazy } from "react";
import { createBrowserRouter } from "react-router";
import { Layout } from "./Layout";
import { RouteError } from "./RouteError";

// One chunk per page; the shell (layout, API client, tokens) loads once.
const Overview = lazy(() => import("../features/overview/OverviewPage"));
const Detect = lazy(() => import("../features/detect/DetectPage"));
const Webcheck = lazy(() => import("../features/webcheck/WebcheckPage"));
const Forensics = lazy(() => import("../features/forensics/ForensicsPage"));
const Bitcoin = lazy(() => import("../features/bitcoin/BitcoinPage"));
const Migration = lazy(() => import("../features/bitcoin/MigrationPage"));
const Settings = lazy(() => import("../features/settings/SettingsPage"));
const NotFound = lazy(() => import("./NotFound"));

export const router = createBrowserRouter([
  {
    path: "/",
    Component: Layout,
    ErrorBoundary: RouteError,
    children: [
      { index: true, Component: Overview },
      { path: "detect", Component: Detect },
      { path: "webcheck", Component: Webcheck },
      { path: "forensics", Component: Forensics },
      { path: "bitcoin", Component: Bitcoin },
      { path: "bitcoin/migration/:addressType", Component: Migration },
      { path: "settings", Component: Settings },
      { path: "*", Component: NotFound },
    ],
  },
]);
