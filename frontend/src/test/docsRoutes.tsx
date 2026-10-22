// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Route, Routes } from "react-router";
import DocsPage from "../features/docs/DocsPage";

/** The docs pages at /docs and /docs/*, for tests. */
export function DocsRoutes() {
  return (
    <Routes>
      <Route path="/docs" element={<DocsPage />} />
      <Route path="/docs/*" element={<DocsPage />} />
    </Routes>
  );
}
