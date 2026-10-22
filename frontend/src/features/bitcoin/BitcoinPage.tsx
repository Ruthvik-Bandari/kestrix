// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation } from "@tanstack/react-query";
import { useState, type SubmitEvent } from "react";
import { Link } from "react-router";
import { dashboardPath } from "../../app/paths";
import { Icon } from "../../components/Icon";
import { FailedRequest, LiveStatus, PendingPanel, ReportSection, ToolLayout, useFocusOnArrival, VerdictCard } from "../../components/report";
import { ReportOutline, stageOf, Workspace } from "../../components/toolframe";
import { Badge, Button, CopyButton, Field, RawJson, Switch } from "../../components/ui";
import { tones, type Tone } from "../../components/tone";
import { api } from "../../lib/api";
import { plural, satsToBtc } from "../../lib/format";
import type { AddressAssessment, PublicTestnet, Risk, ScanResult } from "../../lib/types";
import { outlines } from "../tools/frame";
import { ToolFrame } from "../tools/ToolHeader";
import { Guardian } from "./Guardian";

const MAX_ADDRESSES = 100;

const riskMeta: Record<Risk, { tone: Tone; label: string }> = {
  critical: { tone: "crit", label: "Critical" },
  high: { tone: "high", label: "High" },
  low: { tone: "ok", label: "Low" },
  unknown: { tone: "neutral", label: "Unknown" },
};

const exposureText = {
  exposed: "Public key visible on chain",
  not_exposed: "Public key not yet revealed",
  unknown: "Exposure unknown",
};

function parseAddresses(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function summaryHeadline(result: ScanResult): { tone: Tone; title: string } {
  const { critical, high } = result.summary.by_risk;
  const urgent = critical + high;
  const unknown = result.summary.by_risk.unknown;
  if (urgent === 0 && unknown > 0)
    return {
      tone: "med",
      title: `No address is known to be exposed, but ${unknown.toString()} of ${result.summary.total.toString()} could not be judged. Unknown is not safe.`,
    };
  if (urgent === 0)
    return { tone: "ok", title: `None of the ${plural(result.summary.total, "address", "addresses")} need urgent action.` };
  return {
    tone: critical > 0 ? "crit" : "high",
    title: `${plural(urgent, "address", "addresses")} of ${result.summary.total} ${urgent === 1 ? "has" : "have"} a public key a quantum computer could target.`,
  };
}

function AddressItem({ item }: { item: AddressAssessment }) {
  const meta = riskMeta[item.risk];
  return (
    <li className="relative py-4 pr-4 pl-5 sm:pr-5 sm:pl-6">
      <span className={`absolute inset-y-0 left-0 w-1 ${tones[meta.tone].mark}`} aria-hidden="true" />
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={meta.tone}>{meta.label} risk</Badge>
        <span className="text-[0.8125rem] text-ink-2">
          <span className="font-medium text-ink">{item.address_type}</span>
          {item.network ? ` · ${item.network}` : ""} · {exposureText[item.key_exposure]}
        </span>
      </div>
      <div className="mt-2 flex items-start gap-1">
        <code className="min-w-0 flex-1 pt-1.5 text-[0.8125rem] break-all text-ink">{item.input}</code>
        <CopyButton text={item.input} label="Copy address" className="flex-none" />
      </div>
      <p className="mt-2 max-w-[68ch] text-ink-2">{item.explanation}</p>
      {item.risk === "unknown" ? (
        <p className="mt-2 max-w-[68ch] rounded-lg bg-inset px-3 py-2 text-[0.875rem] text-ink-2">
          <span className="font-medium text-ink">Unknown is not safe.</span> From the address alone Kestrix cannot tell whether its
          public key has been revealed. Turn on the chain lookup to check, or treat the address as exposed.
        </p>
      ) : null}
      <p className="mt-2 max-w-[68ch]">
        <span className="font-medium">What to do: </span>
        <span className="text-ink-2">{item.recommendation}</span>
      </p>
      {item.chain_activity ? (
        <p className="mt-2 text-[0.8125rem] text-ink-3">
          {item.chain_activity.chain} via {item.chain_activity.source}: {plural(item.chain_activity.funded_outputs, "output")}{" "}
          received, {item.chain_activity.spent_outputs} spent, balance {satsToBtc(item.chain_activity.balance_sats)}
        </p>
      ) : null}
      <Link to={dashboardPath(`bitcoin/migration/${item.address_type}`)} className="link mt-3 inline-flex min-h-11 items-center gap-1 text-[0.875rem] sm:min-h-0">
        Migration plan for {item.address_type}
        <Icon name="arrowRight" size={14} />
      </Link>
    </li>
  );
}

function Results({ result, lookedUp }: { result: ScanResult; lookedUp: boolean }) {
  const heading = useFocusOnArrival(result);
  const verdict = summaryHeadline(result);
  return (
    <section aria-labelledby="btc-result" className="@container reveal scroll-mt-6 space-y-6">
      <VerdictCard
        tone={verdict.tone}
        label="Scan results"
        headingId="btc-result"
        headingRef={heading}
        title={verdict.title}
        aside={
          <ul aria-label="Addresses by risk" className="grid grid-cols-2 gap-x-4 gap-y-1">
            {(["critical", "high", "low", "unknown"] as const).map((risk) => (
              <li key={risk} className="flex items-baseline justify-between gap-2">
                <span className={`flex items-center gap-1.5 text-[0.875rem] font-medium ${tones[riskMeta[risk].tone].text}`}>
                  <Icon name={tones[riskMeta[risk].tone].icon} size={14} />
                  {riskMeta[risk].label}
                </span>
                <span className="num text-lg font-semibold">{result.summary.by_risk[risk]}</span>
              </li>
            ))}
          </ul>
        }
      >
        <p>
          {lookedUp
            ? "The addresses were looked up on mempool.space, so spend history is part of the judgement."
            : "No chain lookup was made. Risk is judged from each address type alone, so some addresses are unknown."}{" "}
          Nothing was moved or signed: Kestrix only reads public addresses.
        </p>
      </VerdictCard>
      <ReportSection id="btc-addresses" icon="listChecks" title="Addresses" count={result.results.length} level={2} flat>
        <ul className="divide-y divide-line overflow-hidden rounded-xl border border-line bg-surface-solid">
          {result.results.map((item, i) => (
            <AddressItem key={`${item.input}-${i}`} item={item} />
          ))}
        </ul>
      </ReportSection>
      <RawJson data={result} filename="kestrix-bitcoin-scan.json" />
    </section>
  );
}

function Before() {
  return (
    <ReportOutline sections={outlines.bitcoin}>
      <div>
        <h3 className="font-semibold">What stays uncertain</h3>
        <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-2">
          <li>A hash-based address is unknown until its spend history is checked. Unknown is not safe.</li>
          <li>The scan is read-only: it cannot move coins and never needs a private key.</li>
          <li>
            Moving coins is explained in a{" "}
            <Link to={dashboardPath("bitcoin/migration/P2PKH")} className="link">
              migration plan
            </Link>{" "}
            per address type.
          </li>
        </ul>
      </div>
    </ReportOutline>
  );
}

export default function BitcoinPage() {
  const [text, setText] = useState("");
  const [lookup, setLookup] = useState(false);
  const [testnet, setTestnet] = useState<PublicTestnet>("testnet4");
  const [error, setError] = useState<string | null>(null);
  const scan = useMutation({
    mutationFn: (input: { addresses: string[]; lookup: boolean; testnet: PublicTestnet }) =>
      api.bitcoinScan(input.addresses, input.lookup, input.testnet),
  });
  const addresses = parseAddresses(text);
  const tooMany = addresses.length > MAX_ADDRESSES;

  function run() {
    if (addresses.length === 0) {
      setError("Paste at least one address.");
      return;
    }
    if (tooMany) {
      setError(`Scan at most ${MAX_ADDRESSES} addresses at a time.`);
      return;
    }
    setError(null);
    scan.mutate({ addresses, lookup, testnet });
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    run();
  }

  const input = (
    <form onSubmit={submit} noValidate aria-label="Scan Bitcoin addresses">
      <Workspace
        steps={[
          {
            key: "addresses",
            title: "Public addresses",
            children: (
              <>
                <div className="flex gap-3 rounded-lg bg-inset px-3.5 py-3 text-[0.875rem]">
                  <Icon name="key" size={18} className="mt-0.5 flex-none text-accent-text" />
                  <p className="text-ink-2">
                    <span className="font-medium text-ink">Only paste public addresses.</span> Kestrix never needs your private keys or
                    seed phrase and will never ask for them. Anyone who asks for your seed phrase is trying to steal your coins.
                  </p>
                </div>
                <Field
                  htmlFor="btc-addresses"
                  label="Addresses"
                  hint={
                    <>
                      One per line, up to {MAX_ADDRESSES}.{" "}
                      <span className={tooMany ? "font-medium text-crit" : undefined}>
                        {addresses.length} / {MAX_ADDRESSES}
                      </span>
                    </>
                  }
                  error={error}
                >
                  <textarea
                    id="btc-addresses"
                    className="field"
                    rows={7}
                    spellCheck={false}
                    autoComplete="off"
                    value={text}
                    onChange={(e) => {
                      setText(e.target.value);
                      setError(null);
                    }}
                    aria-invalid={error || tooMany ? true : undefined}
                    aria-describedby={`btc-addresses-hint${error ? " btc-addresses-error" : ""}`}
                    placeholder={"bc1q…\n1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}
                  />
                </Field>
              </>
            ),
          },
          {
            key: "lookup",
            title: "Chain lookup",
            optional: true,
            children: (
              <>
                <Switch
                  checked={lookup}
                  onChange={setLookup}
                  label="Look up spend history on the blockchain"
                  description="Off by default. When on, the addresses are sent to mempool.space, a public service, which can link them to your IP address. Without it, risk is judged from the address type alone."
                />
                {lookup ? (
                  <Field htmlFor="btc-testnet" label="Test network for test addresses" hint="Only used for tb1 / test-network addresses.">
                    <select
                      id="btc-testnet"
                      className="field max-w-60"
                      value={testnet}
                      onChange={(e) => {
                        setTestnet(e.target.value === "signet" ? "signet" : "testnet4");
                      }}
                      aria-describedby="btc-testnet-hint"
                    >
                      <option value="testnet4">testnet4</option>
                      <option value="signet">signet</option>
                    </select>
                  </Field>
                ) : null}
              </>
            ),
          },
          {
            key: "run",
            title: "Scan",
            run: true,
            children: (
              <>
                <Button type="submit" icon="search" className="w-full" pending={scan.isPending} pendingLabel="Scanning…">
                  {lookup ? "Scan and look up on mempool.space" : "Scan addresses"}
                </Button>
                <p className="hint">
                  {lookup
                    ? "This sends your addresses and IP address to mempool.space."
                    : "Offline: nothing leaves this computer."}
                </p>
              </>
            ),
          },
        ]}
      />
    </form>
  );

  const stage = stageOf({ ready: addresses.length > 0, pending: scan.isPending, failed: scan.isError, done: Boolean(scan.data) });

  return (
    <ToolFrame page="bitcoin">
      <ToolLayout input={input} stage={stage}>
        <LiveStatus
          pending={scan.isPending}
          done={scan.isSuccess}
          pendingText="Scanning the addresses…"
          doneText="Scan finished. The result is below."
        />
        {scan.isPending ? (
          <PendingPanel title="Scanning the addresses">
            {scan.variables.lookup
              ? "Reading each address and asking mempool.space for its spend history."
              : "Reading each address. No network request is made."}
          </PendingPanel>
        ) : scan.isError ? (
          <FailedRequest error={scan.error} onRetry={run} />
        ) : scan.data ? (
          <Results result={scan.data} lookedUp={scan.variables.lookup} />
        ) : (
          <Before />
        )}

        <Guardian
          onUseAddresses={(found) => {
            setText(found.join("\n"));
            document.getElementById("btc-addresses")?.focus();
          }}
        />

        <ReportSection id="btc-plans" icon="route" title="Migration plans by address type" level={2} flat>
          <ul className="flex flex-wrap gap-2">
            {(["P2PK", "P2PKH", "P2SH", "P2WPKH", "P2WSH", "P2TR"] as const).map((type) => (
              <li key={type}>
                <Link to={dashboardPath(`bitcoin/migration/${type}`)} className="btn btn-secondary btn-sm font-mono">
                  {type}
                </Link>
              </li>
            ))}
          </ul>
        </ReportSection>
      </ToolLayout>
    </ToolFrame>
  );
}
