// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../lib/api";
import { Badge, Button, ErrorState, Field, Panel } from "./ui";

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

describe("Button", () => {
  it("is a primary button by default", () => {
    render(<Button>Run check</Button>);
    expect(screen.getByRole("button", { name: "Run check" }).className).toContain("btn-primary");
  });

  it("pending keeps focusability, announces busy, swaps the label and ignores clicks", () => {
    const onClick = vi.fn();
    render(
      <Button pending pendingLabel="Checking" onClick={onClick}>
        Run check
      </Button>,
    );
    const button = screen.getByRole("button", { name: "Checking" });
    expect(button.getAttribute("aria-busy")).toBe("true");
    expect(button.getAttribute("aria-disabled")).toBe("true");
    expect(button.hasAttribute("disabled")).toBe(false);
    fireEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("disabled uses the native attribute", () => {
    render(<Button disabled>Run check</Button>);
    expect(screen.getByRole("button").hasAttribute("disabled")).toBe(true);
  });
});

describe("Field", () => {
  it("links label, hint and error to the control", () => {
    render(
      <Field htmlFor="url" label="Address" hint="Example: https://example.com" error="Enter a valid URL">
        <input id="url" className="field" />
      </Field>,
    );
    const input = screen.getByLabelText("Address");
    expect(input.getAttribute("aria-describedby")).toBe("url-hint url-error");
    expect(input.getAttribute("aria-invalid")).toBe("true");
  });

  it("keeps a caller-provided aria-describedby", () => {
    render(
      <Field htmlFor="sel" label="Network" hint="Only for test addresses">
        <select id="sel" aria-describedby="sel-hint" />
      </Field>,
    );
    expect(screen.getByLabelText("Network").getAttribute("aria-describedby")).toBe("sel-hint");
  });

  it("marks optional fields in the label", () => {
    render(
      <Field htmlFor="x" label="Domains" optional>
        <input id="x" className="field" />
      </Field>,
    );
    expect(screen.getByText("(optional)")).toBeTruthy();
  });
});

describe("Badge and Panel", () => {
  it("badge shows text beside its icon", () => {
    const { container } = render(<Badge tone="crit">High</Badge>);
    expect(screen.getByText("High")).toBeTruthy();
    expect(container.querySelector("svg")).toBeTruthy();
  });

  it("panel is a solid panel", () => {
    const { container } = render(<Panel>Body</Panel>);
    expect((container.firstChild as HTMLElement).className).toContain("panel");
  });
});
