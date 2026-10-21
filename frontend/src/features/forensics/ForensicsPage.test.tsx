// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FileReport, UrlReport } from "../../lib/types";
import ForensicsPage from "./ForensicsPage";

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <ForensicsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const urlReport: UrlReport = {
  url: "http://paypa1-login.example.top/verify",
  scheme: "http",
  host: "paypa1-login.example.top",
  unicode_host: "paypa1-login.example.top",
  registrable_domain: "example.top",
  score: 70,
  level: "high",
  score_note: "A rule-based score, not a probability.",
  findings: [
    { id: "url.no_tls", severity: "medium", title: "Link does not use HTTPS", explanation: "Plain HTTP." },
    { id: "url.brand_lookalike", severity: "high", title: "Host imitates a known brand", explanation: "paypa1 looks like paypal." },
  ],
};

const fileReport: FileReport = {
  filename: "invoice.pdf",
  size: 2048,
  hashes: { md5: "m".repeat(32), sha1: "s".repeat(40), sha256: "a".repeat(64), sha512: "b".repeat(128) },
  file_type: { id: "pe", label: "Windows executable", executable: true, extension: "pdf", expected_extensions: ["exe"], extension_mismatch: true },
  entropy: {
    overall: 5.1,
    block_size: 256,
    block_count: 8,
    points_span_blocks: 1,
    points: [{ offset: 0, entropy: 5.1 }],
    high_entropy_threshold: 7.2,
    high_entropy_regions: [],
    high_entropy_region_count: 0,
    high_entropy_bytes: 0,
  },
  byte_histogram: Array.from({ length: 256 }, (_, i) => (i === 65 ? 10 : 0)),
  printable_ratio: 0.5,
  exif: null,
  exif_status: "not_image",
  findings: [{ id: "file.extension_mismatch", severity: "high", title: "Name disguises an .exe file as .pdf", explanation: "Content is a program." }],
};

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  vi.stubGlobal("matchMedia", () => ({ matches: false }));
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      disconnect() {}
      unobserve() {}
    },
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("file and link tabs", () => {
  it("opens on the File tab by default", () => {
    renderAt("/forensics");
    expect(screen.getByRole("tab", { name: "File" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByLabelText(/choose a file/i)).toBeTruthy();
    expect(screen.getByText(/never run/i)).toBeTruthy();
  });

  it("opens the Link tab from ?tab=url and says the link is never fetched", () => {
    renderAt("/forensics?tab=url");
    expect(screen.getByRole("tab", { name: "Link" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByLabelText("Link to check")).toBeTruthy();
    expect(screen.getAllByText(/never opened/i).length).toBeGreaterThan(0);
  });

  it("shows how a link breaks down, heuristic signals worst first, and moves focus to the result", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(urlReport))));
    renderAt("/forensics?tab=url");
    fireEvent.change(screen.getByLabelText("Link to check"), { target: { value: urlReport.url } });
    fireEvent.click(screen.getByRole("button", { name: "Check link" }));
    const heading = await screen.findByRole("heading", { level: 2, name: "High suspicion" });
    await waitFor(() => {
      expect(document.activeElement).toBe(heading);
    });
    expect(screen.getByText("paypa1-login")).toBeTruthy();
    expect(screen.getAllByText("example.top").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/not a probability/i).length).toBeGreaterThan(0);
    const titles = [...document.querySelectorAll("li > details > summary")].map((n) => n.textContent);
    expect(titles[0]).toContain("imitates a known brand");
    expect(screen.queryByRole("link", { name: /paypa1/ })).toBeNull();
  });

  it("keeps the link text after an error", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json({ reason: "invalid_url", detail: "not a link" }, { status: 400 }))));
    renderAt("/forensics?tab=url");
    fireEvent.change(screen.getByLabelText("Link to check"), { target: { value: "nonsense" } });
    fireEvent.click(screen.getByRole("button", { name: "Check link" }));
    expect((await screen.findByRole("alert")).textContent).toContain("not a link");
    expect(screen.getByRole<HTMLInputElement>("textbox", { name: "Link to check" }).value).toBe("nonsense");
  });

  it("analyzes a chosen file, calls out a type mismatch and keeps hashes copyable", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(fileReport))));
    renderAt("/forensics");
    fireEvent.change(screen.getByLabelText(/choose a file/i), { target: { files: [new File(["MZ"], "invoice.pdf")] } });
    const heading = await screen.findByRole("heading", { level: 2, name: "Type mismatch" });
    await waitFor(() => {
      expect(document.activeElement).toBe(heading);
    });
    expect(screen.getByText(/claims to be \.pdf, but its content is detected as Windows executable/)).toBeTruthy();
    expect(screen.getByText("a".repeat(64))).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy SHA256 hash" })).toBeTruthy();
    expect(screen.getByText("invoice.pdf", { selector: "p" })).toBeTruthy();
  });

  it("refuses a file over the limit before uploading and keeps the picker", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderAt("/forensics");
    const big = new File(["x"], "big.bin");
    Object.defineProperty(big, "size", { value: 51 * 1024 * 1024 });
    fireEvent.change(screen.getByLabelText(/choose a file/i), { target: { files: [big] } });
    expect(screen.getByRole("alert").textContent).toContain("The limit is 50 MB");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByLabelText(/choose a file/i)).toBeTruthy();
  });
});
