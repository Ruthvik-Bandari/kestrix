// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Icon } from "../../../components/Icon";
import { tones, type Tone } from "../../../components/tone";
import { cx } from "../../../components/ui";
import { Compare, useSide } from "../Compare";
import { Pane, Story } from "../parts";
import { bitcoinSample as b } from "../samples";

const RISK_TONE: Record<string, Tone> = { critical: "crit", high: "high", low: "ok", unknown: "neutral" };
const EXPOSURE: Record<string, string> = {
  exposed: "Public key visible on chain",
  not_exposed: "Public key still hidden",
  unknown: "Depends on spend history",
};
const plan = b.plans.P2TR;

function short(text: string): string {
  return text.length > 26 ? `${text.slice(0, 14)}…${text.slice(-8)}` : text;
}

function Wallet() {
  const { side } = useSide();
  const withK = side === "with";
  return (
    <div className="device overflow-hidden rounded-2xl">
      <div className="flex items-center gap-2 border-b border-line px-4 py-2.5 text-[0.8125rem] font-semibold text-ink-2">
        <Icon name="bitcoin" size={15} />
        Your addresses
      </div>
      <ul className="grid gap-3 p-4 sm:grid-cols-2">
        {b.cards.map((card) => {
          const a = card.assessment;
          const tone = tones[RISK_TONE[a.risk] ?? "neutral"];
          return (
            <li
              key={a.input}
              className={cx(
                "coin-card relative overflow-hidden rounded-xl border p-3.5",
                withK && (a.risk === "critical" || a.risk === "high") ? "border-crit-mark/50" : "border-line",
              )}
            >
              <p className="flex items-center justify-between gap-2">
                <span className="text-[0.9375rem] font-semibold text-ink">{card.label}</span>
                {withK ? (
                  <span className={cx("inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[0.6875rem] font-bold uppercase", tone.soft)}>
                    <Icon name={tone.icon} size={11} />
                    {a.risk}
                  </span>
                ) : null}
              </p>
              <code className="mt-1 block text-[0.75rem] text-ink-2" title={a.input}>
                {short(a.input)}
              </code>
              {withK ? (
                <p className="mt-2 text-[0.8125rem] text-ink-2">
                  <span className="font-semibold text-ink">{a.address_type}</span> · {EXPOSURE[a.key_exposure] ?? a.key_exposure}
                  {card.synthetic_history ? (
                    <span className="mt-1 block text-[0.75rem] text-ink-3">
                      synthetic history: {card.synthetic_history.spent_outputs} spent outputs
                    </span>
                  ) : null}
                </p>
              ) : (
                <p className="mt-2 text-[0.8125rem] text-ink-3">Receiving address</p>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function WithAside() {
  return (
    <div className="grid gap-4">
      <div className="glass rounded-xl p-4">
        <p className="text-[0.75rem] font-semibold tracking-[0.1em] text-accent-text uppercase">Migration plan · Taproot savings</p>
        <p className="mt-1 text-[0.9375rem] text-ink">{plan?.summary}</p>
        <ol className="mt-3 grid gap-2">
          {plan?.steps.slice(0, 4).map((step, i) => (
            <li key={step} className="flex gap-2.5 text-[0.8125rem] text-ink-2">
              <span className="step-dot size-6 text-[0.75rem]">{i + 1}</span>
              <span className="pt-0.5">{step}</span>
            </li>
          ))}
        </ol>
      </div>
      <p className="flex gap-2 rounded-xl border border-line bg-inset p-3 text-[0.8125rem] text-ink-2">
        <Icon name="key" size={16} className="mt-0.5 flex-none text-h1" />
        {b.history_note} Read-only: Kestrix cannot sign, send or move coins.
      </p>
    </div>
  );
}

export function BitcoinScene() {
  return (
    <Compare
      name="the bitcoin addresses"
      without={
        <Pane
          device={<Wallet />}
          aside={
            <Story
              steps={[
                { icon: "bitcoin", text: "Four addresses, four strings of letters. They all look equally safe." },
                { icon: "key", text: "Some of them already show their public key to anyone reading the blockchain." },
                { icon: "help", text: "Nothing in the list says which ones." },
              ]}
              outcome={{ title: "You can't plan a move you can't see", text: "The exposed coins sit next to the hidden ones, unmarked." }}
            />
          }
        />
      }
      withKestrix={<Pane device={<Wallet />} aside={<WithAside />} />}
    />
  );
}
