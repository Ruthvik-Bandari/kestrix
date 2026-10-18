import { useMutation } from "@tanstack/react-query";
import { useState, type SubmitEvent } from "react";
import { Link } from "react-router";
import { Icon } from "../../components/Icon";
import { ErrorState, Field, Spinner, Verdict } from "../../components/ui";
import { ApiError, api } from "../../lib/api";
import type { GuardianResult } from "../../lib/types";

const MAX_MESSAGE = 2000;

const intentText: Record<GuardianResult["intent"], string> = {
  scan_addresses: "You want addresses checked",
  explain_risk: "You want the quantum risk explained",
  migration_help: "You want help moving coins",
  set_policy_request: "You asked to change a policy",
  unknown: "Your request wasn't clear",
};

function Answer({ result, onUseAddresses }: { result: GuardianResult; onUseAddresses: (a: string[]) => void }) {
  return (
    <div className="reveal mt-5 space-y-4">
      <div>
        <p className="text-[0.8125rem] font-medium text-ink-3">Understood as</p>
        <p className="font-medium">{intentText[result.intent]}</p>
      </div>

      {/* Deterministic text written by Kestrix, not the model. */}
      <div className="rounded-lg bg-accent-soft px-4 py-3">
        <p className="text-[0.8125rem] font-medium text-accent-text">Next step from Kestrix</p>
        <p className="mt-1 text-ink">{result.next_step}</p>
        <div className="mt-3 flex flex-wrap gap-2">
          {result.addresses.length > 0 ? (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => {
                onUseAddresses(result.addresses);
              }}
            >
              Scan {result.addresses.length === 1 ? "this address" : `these ${result.addresses.length} addresses`}
            </button>
          ) : null}
          {result.address_type ? (
            <Link to={`/bitcoin/migration/${result.address_type}`} className="btn btn-secondary btn-sm">
              {result.address_type} migration plan
            </Link>
          ) : null}
        </div>
      </div>

      {/* Model-written text: untrusted, since a pasted message can steer it. */}
      <figure className="rounded-lg border border-dashed border-line-strong px-4 py-3">
        <figcaption className="flex items-center gap-1.5 text-[0.8125rem] font-medium text-ink-2">
          <Icon name="sparkle" size={14} />
          AI-generated, unverified
        </figcaption>
        <blockquote className="mt-1 whitespace-pre-line text-ink-2">{result.model_summary}</blockquote>
        <p className="mt-2 text-xs text-ink-3">Model {result.model}. Check anything important against the scan results.</p>
      </figure>

      {result.ignored_addresses.length > 0 ? (
        <p className="text-[0.8125rem] text-ink-3">
          Ignored as invalid: <code className="break-all">{result.ignored_addresses.join(", ")}</code>
        </p>
      ) : null}
    </div>
  );
}

export function Guardian({ onUseAddresses }: { onUseAddresses: (addresses: string[]) => void }) {
  const [message, setMessage] = useState("");
  const ask = useMutation({ mutationFn: api.guardian });
  const keyMissing = ask.error instanceof ApiError && ask.error.reason === "ai_key_missing" ? ask.error : null;

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (message.trim()) ask.mutate(message.trim());
  }

  return (
    <section aria-labelledby="guardian-title" className="panel p-5 sm:p-6">
      <h2 id="guardian-title" className="flex items-center gap-2 text-lg font-semibold">
        <Icon name="sparkle" size={18} className="text-accent-text" />
        Ask the guardian
      </h2>
      <p className="mt-1 text-ink-2">
        Describe what you want in your own words. An AI model works out what you mean; Kestrix decides what happens
        next. Uses your Anthropic API key.
      </p>
      <form onSubmit={submit} className="mt-4 space-y-3">
        <Field htmlFor="guardian-message" label="Your question" hint={`${message.length} / ${MAX_MESSAGE} characters. Never include a seed phrase or private key.`}>
          <textarea
            id="guardian-message"
            className="field font-sans text-[0.9375rem]"
            rows={4}
            maxLength={MAX_MESSAGE}
            value={message}
            onChange={(e) => {
              setMessage(e.target.value);
            }}
            aria-describedby="guardian-message-hint"
            placeholder="Is my old 1… address at risk, and how do I move it?"
          />
        </Field>
        <button type="submit" className="btn btn-secondary" disabled={!message.trim() || ask.isPending}>
          {ask.isPending ? <Spinner /> : null}
          {ask.isPending ? "Asking…" : "Ask"}
        </button>
      </form>
      <div aria-live="polite">
        {keyMissing ? (
          <div className="mt-5">
            <Verdict tone="accent" icon="key" title="The guardian needs an Anthropic API key">
              <p>
                Add a key in{" "}
                <Link to="/settings" className="link">
                  Settings
                </Link>
                , or set the <code>ANTHROPIC_API_KEY</code> environment variable before starting Kestrix. The address
                scanner above works without it.
              </p>
              <p className="mt-2 text-[0.8125rem] text-ink-3">Server said: {keyMissing.detail}</p>
            </Verdict>
          </div>
        ) : ask.isError ? (
          <div className="mt-5">
            <ErrorState error={ask.error} />
          </div>
        ) : null}
        {ask.data ? <Answer result={ask.data} onUseAddresses={onUseAddresses} /> : null}
      </div>
    </section>
  );
}
