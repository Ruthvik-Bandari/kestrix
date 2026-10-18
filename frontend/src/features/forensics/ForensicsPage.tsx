// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useSearchParams } from "react-router";
import { Tabs } from "../../components/Tabs";
import { PageHeader } from "../../components/ui";
import { useTitle } from "../../lib/useTitle";
import { FileAnalyzer } from "./FileAnalyzer";
import { UrlAnalyzer } from "./UrlAnalyzer";

type Tab = "file" | "url";

export default function ForensicsPage() {
  useTitle("Forensics");
  const [params, setParams] = useSearchParams();
  const tab: Tab = params.get("tab") === "url" ? "url" : "file";
  return (
    <>
      <PageHeader
        title="Forensics"
        lede="Check whether a file is what it claims to be, spot hidden encrypted data and location-revealing photos, or test a suspicious link without opening it."
      />
      <Tabs<Tab>
        label="What to analyze"
        value={tab}
        onChange={(next) => {
          setParams(next === "url" ? { tab: "url" } : {}, { replace: true });
        }}
        items={[
          { key: "file", label: "File" },
          { key: "url", label: "Link" },
        ]}
      >
        {tab === "file" ? <FileAnalyzer /> : <UrlAnalyzer />}
      </Tabs>
    </>
  );
}
