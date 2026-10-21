// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useSearchParams } from "react-router";
import { Tabs } from "../../components/Tabs";
import { ToolHeader } from "../tools/ToolHeader";
import { FileAnalyzer } from "./FileAnalyzer";
import { UrlAnalyzer } from "./UrlAnalyzer";

type Tab = "file" | "url";

export default function ForensicsPage() {
  const [params, setParams] = useSearchParams();
  const tab: Tab = params.get("tab") === "url" ? "url" : "file";
  return (
    <>
      <ToolHeader page="forensics" />
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
