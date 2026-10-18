// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Link } from "react-router";
import { PageHeader } from "../components/ui";
import { useTitle } from "../lib/useTitle";

export default function NotFound() {
  useTitle("Page not found");
  return (
    <>
      <PageHeader title="Page not found" lede="There is nothing at this address in the dashboard." />
      <Link to="/" className="btn btn-secondary">
        Back to the overview
      </Link>
    </>
  );
}
