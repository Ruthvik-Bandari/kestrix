// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useSearchParams } from "react-router";
import { HowItWorks, type HowItWorksContent } from "../../components/HowItWorks";
import { Tabs } from "../../components/Tabs";
import { PageHeader } from "../../components/ui";
import { useTitle } from "../../lib/useTitle";
import { FileAnalyzer } from "./FileAnalyzer";
import { UrlAnalyzer } from "./UrlAnalyzer";

type Tab = "file" | "url";

const howItWorks: HowItWorksContent = {
  id: "forensics",
  name: "Forensics",
  purpose:
    "Find out what a file really is, and whether a link shows common phishing signs, without running the file or opening the link.",
  steps: [
    "Choose a file (up to 50 MB) or paste a link.",
    "For a file: four hashes (MD5, SHA-1, SHA-256, SHA-512) to look up elsewhere, the real format from its first bytes, entropy per block to spot packed or encrypted data, and photo metadata such as GPS location.",
    "For a link: offline checks of the text, such as IP-address hosts, look-alike letters, brand names in subdomains, shorteners and embedded credentials.",
    "Each finding comes with a severity and a plain explanation. The link score is a heuristic, not a probability.",
  ],
  usefulWhen: [
    "A download or attachment you are unsure about.",
    "A photo you are about to share.",
    "A link from an email or a message.",
  ],
  doesNot: [
    "It is not a malware or phishing verdict: a clean result means none of the checks fired.",
    "It never executes, decompresses or renders the file.",
    "It never fetches the link.",
  ],
};

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
      <HowItWorks content={howItWorks} />
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
