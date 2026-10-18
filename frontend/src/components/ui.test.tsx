// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApiError } from "../lib/api";
import { ErrorState } from "./ui";

describe("ErrorState", () => {
  it("shows a friendly title and the server detail", () => {
    render(<ErrorState error={new ApiError(502, "target_unreachable", "connection refused by example.com")} />);
    expect(screen.getByRole("alert").textContent).toContain("Couldn't reach that address");
    expect(screen.getByText("connection refused by example.com")).toBeTruthy();
  });

  it("explains 413 size limits in megabytes", () => {
    render(<ErrorState error={new ApiError(413, "input_too_large", "request body exceeds 62914560 bytes")} />);
    expect(screen.getByRole("alert").textContent).toContain("60 MB");
  });

  it("explains a cross-site refusal", () => {
    render(<ErrorState error={new ApiError(403, "cross_site_request", "requests from other websites are not allowed")} />);
    expect(screen.getByRole("alert").textContent).toContain("only accepts actions from its own dashboard");
  });
});
