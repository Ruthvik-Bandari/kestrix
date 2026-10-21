// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation } from "@tanstack/react-query";
import { useEffect, useRef, useState, type SubmitEvent } from "react";
import { Link } from "react-router";
import { Icon } from "../../components/Icon";
import { Badge, CopyButton, ErrorState, Field, RawJson, SectionTitle, Spinner, Switch, Verdict } from "../../components/ui";
import { tones, type Tone } from "../../components/tone";
import { api } from "../../lib/api";
import { plural, satsToBtc } from "../../lib/format";
import { scrollBehavior } from "../../lib/motion";
import type { AddressAssessment, PublicTestnet, Risk, ScanResult } from "../../lib/types";
import { ToolHeader } from "../tools/ToolHeader";
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
    <li className="px-4 py-4 sm:px-5">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={meta.tone}>{meta.label} risk</Badge>
        <span className="text-[0.8125rem] text-ink-2">
          {item.address_type}
          {item.network ? ` · ${item.network}` : ""} · {exposureText[item.key_exposure]}
        </span>
      </div>
      <div className="mt-2 flex items-start gap-1">
        <code className="min-w-0 flex-1 pt-1.5 text-[0.8125rem] break-all text-ink">{item.input}</code>
        <CopyButton text={item.input} label="Copy address" className="flex-none" />
      </div>
      <p className="mt-2 max-w-[72ch] text-ink-2">{item.explanation}</p>
      <p className="mt-2 max-w-[72ch]">
        <span className="font-medium">What to do: </span>
        <span className="text-ink-2">{item.recommendation}</span>
      </p>
      {item.chain_activity ? (
        <p className="mt-2 text-[0.8125rem] text-ink-3">
          {item.chain_activity.chain} via {item.chain_activity.source}: {plural(item.chain_activity.funded_outputs, "output")}{" "}
          received, {item.chain_activity.spent_outputs} spent, balance {satsToBtc(item.chain_activity.balance_sats)}
        </p>
      ) : null}
      <Link to={`/bitcoin/migration/${item.address_type}`} className="link mt-3 inline-flex items-center gap-1 text-[0.875rem]">
        Migration plan for {item.address_type}
        <Icon name="arrowRight" size={14} />
      </Link>
    </li>
  );
}

function Results({ result }: { result: ScanResult }) {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    ref.current?.focus();
    ref.current?.scrollIntoView({ block: "start", behavior: scrollBehavior() });
  }, [result]);
  const verdict = summaryHeadline(result);
  return (
    <section aria-labelledby="btc-result" className="reveal mt-10 scroll-mt-6 border-t border-line pt-8">
      <h2 id="btc-result" ref={ref} tabIndex={-1} className="mb-4 text-xl font-semibold outline-none">
        Scan results
      </h2>
      <Verdict tone={verdict.tone} title={verdict.title} />
      <ul className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4" aria-label="Addresses by risk">
        {(["critical", "high", "low", "unknown"] as const).map((risk) => (
          <li key={risk} className="panel px-4 py-3">
            <p className={`flex items-center gap-1.5 text-[0.875rem] font-medium ${tones[riskMeta[risk].tone].text}`}>
              <Icon name={tones[riskMeta[risk].tone].icon} size={15} />
              {riskMeta[risk].label}
            </p>
            <p className="mt-1 text-2xl font-semibold">{result.summary.by_risk[risk]}</p>
          </li>
        ))}
      </ul>
      <ul className="mt-6 divide-y divide-line rounded-lg border border-line bg-surface">
        {result.results.map((item, i) => (
          <AddressItem key={`${item.input}-${i}`} item={item} />
        ))}
      </ul>
      <div className="mt-6">
        <RawJson data={result} filename="kestrix-bitcoin-scan.json" />
      </div>
    </section>
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

  function submit(event: SubmitEvent) {
    event.preventDefault();
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

  return (
    <>
      <ToolHeader page="bitcoin" />

      <div className="mb-6 flex gap-3 rounded-xl border border-line bg-surface px-4 py-3">
        <Icon name="key" size={20} className="mt-0.5 flex-none text-accent-text" />
        <p className="text-ink-2">
          <span className="font-medium text-ink">Only paste public addresses.</span> Kestrix never needs your private
          keys or seed phrase and will never ask for them. Anyone who asks for your seed phrase is trying to steal your
          coins.
        </p>
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <form onSubmit={submit} noValidate className="panel space-y-5 p-5 sm:p-6">
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
          <button type="submit" className="btn btn-primary" disabled={scan.isPending}>
            {scan.isPending ? <Spinner /> : <Icon name="search" size={16} />}
            {scan.isPending ? "Scanning…" : "Scan addresses"}
          </button>
          <div aria-live="polite" className="sr-only">
            {scan.isSuccess ? "Scan finished. Results below." : ""}
          </div>
        </form>

        <Guardian
          onUseAddresses={(found) => {
            setText(found.join("\n"));
            document.getElementById("btc-addresses")?.focus();
          }}
        />
      </div>

      {scan.isError ? (
        <div className="mt-8">
          <ErrorState error={scan.error} />
        </div>
      ) : null}
      {scan.data ? <Results result={scan.data} /> : null}

      <section aria-labelledby="plans-title" className="mt-12 border-t border-line pt-8">
        <SectionTitle id="plans-title">Migration plans by address type</SectionTitle>
        <ul className="flex flex-wrap gap-2">
          {(["P2PK", "P2PKH", "P2SH", "P2WPKH", "P2WSH", "P2TR"] as const).map((type) => (
            <li key={type}>
              <Link to={`/bitcoin/migration/${type}`} className="btn btn-secondary btn-sm font-mono">
                {type}
              </Link>
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}
