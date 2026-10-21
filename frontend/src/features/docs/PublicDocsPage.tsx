// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { PublicShell } from "../../components/PublicShell";
import { PublicDocsBody } from "./DocsPage";

/** The documentation without an account (hosted "/docs"): the in-app pages inside the public header and footer. */
export default function PublicDocsPage() {
  return (
    <PublicShell width="docs">
      <PublicDocsBody />
    </PublicShell>
  );
}
