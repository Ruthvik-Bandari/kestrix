// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type SubmitEvent } from "react";
import { Icon } from "../../components/Icon";
import { ThemeSwitch } from "../../components/ThemeSwitch";
import { Button, ErrorState, Field, PageHeader, Skeleton, StatusPill } from "../../components/ui";
import { api } from "../../lib/api";
import { keys, useSettings } from "../../lib/queries";
import { isHosted } from "../../lib/mode";
import { useTitle } from "../../lib/useTitle";
import { AccountMenu } from "../../app/AccountMenu";
import { HistorySetting } from "../history/HistorySetting";

const MIN_KEY = 20;
const MAX_KEY = 512;

export default function SettingsPage() {
  useTitle("Settings");
  const settings = useSettings();
  const queryClient = useQueryClient();
  const [key, setKey] = useState("");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [saved, setSaved] = useState<"set" | "cleared" | null>(null);
  const update = useMutation({
    mutationFn: api.setAnthropicKey,
    onSuccess: (_, value) => {
      setKey("");
      setSaved(value === null ? "cleared" : "set");
      void queryClient.invalidateQueries({ queryKey: keys.settings });
    },
  });
  const configured = settings.data?.anthropic_key_configured === true;
  const hosted = isHosted();

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const value = key.trim();
    if (value.length < MIN_KEY || value.length > MAX_KEY) {
      setFieldError(`An Anthropic API key is between ${MIN_KEY} and ${MAX_KEY} characters.`);
      return;
    }
    setFieldError(null);
    setSaved(null);
    update.mutate(value);
  }

  return (
    <>
      <PageHeader
        title="Settings"
        lede={
          hosted
            ? "Your results history, your account and how the dashboard looks."
            : "Your results history, the optional AI key for the Bitcoin guardian, and how the dashboard looks."
        }
      />

      <div className="grid items-start gap-6 xl:grid-cols-2 xl:gap-8">
        <div className="min-w-0 space-y-6">
          <HistorySetting />

          <section aria-labelledby="look-title" className="panel p-5 sm:p-6">
            <h2 id="look-title" className="text-lg font-semibold tracking-[-0.01em]">
              Appearance
            </h2>
            <p className="mt-1 mb-4 text-[0.875rem] text-ink-2">Light, dark or the setting your device uses. Saved in this browser only.</p>
            <div className="max-w-xs">
              <ThemeSwitch />
            </div>
          </section>
        </div>

        <div className="min-w-0 space-y-6">
          {hosted ? (
            <section aria-labelledby="account-title" className="panel p-5 sm:p-6">
              <h2 id="account-title" className="text-lg font-semibold tracking-[-0.01em]">
                Your account
              </h2>
              <p className="mt-1 mb-4 text-[0.875rem] text-ink-2">
                Signing out ends this sign-in. Deleting your account removes it and your saved results, and signs you out everywhere.
                That cannot be undone.
              </p>
              <AccountMenu />
            </section>
          ) : (
            <section aria-labelledby="key-title" className="panel p-5 sm:p-6">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <h2 id="key-title" className="text-lg font-semibold tracking-[-0.01em]">
                  Anthropic API key
                </h2>
                {settings.isPending ? (
                  <Skeleton className="h-7 w-32" />
                ) : settings.isError ? null : (
                  <StatusPill tone={configured ? "ok" : "neutral"}>{configured ? "Key configured" : "No key set"}</StatusPill>
                )}
              </div>
              <p className="mt-2 max-w-[68ch] text-ink-2">
                Optional. Only the Bitcoin guardian uses it, and only when you ask it a question; using it sends your question to
                Anthropic. Everything else in Kestrix works without a key. The key is never shown again, returned by the API,
                logged, or written to evidence files.
              </p>
              {settings.isError ? (
                <div className="mt-4">
                  <ErrorState error={settings.error} />
                </div>
              ) : null}

              <form onSubmit={submit} noValidate className="mt-5 space-y-4" aria-label="Anthropic API key">
                <Field
                  htmlFor="anthropic-key"
                  label={configured ? "Replace the key" : "Add a key"}
                  hint="Paste a key from console.anthropic.com. It is stored on this computer only."
                  error={fieldError}
                >
                  <input
                    id="anthropic-key"
                    type="password"
                    className="field font-mono"
                    autoComplete="off"
                    spellCheck={false}
                    value={key}
                    onChange={(e) => {
                      setKey(e.target.value);
                      setFieldError(null);
                    }}
                    aria-invalid={fieldError ? true : undefined}
                    aria-describedby={`anthropic-key-hint${fieldError ? " anthropic-key-error" : ""}`}
                    placeholder="sk-ant-…"
                  />
                </Field>
                <div className="flex flex-wrap items-center gap-3">
                  <Button type="submit" disabled={!key.trim()} pending={update.isPending && update.variables !== null}>
                    <Icon name="lock" size={16} />
                    Save key
                  </Button>
                  <span aria-live="polite" className="text-[0.875rem] font-medium text-ok">
                    {saved === "set" ? "Key saved." : saved === "cleared" ? "Saved key removed." : ""}
                  </span>
                </div>
                {update.isError ? <ErrorState error={update.error} /> : null}
              </form>

              {configured ? (
                <div className="mt-5 border-t border-line pt-4">
                  <h3 className="font-medium text-ink">Remove the saved key</h3>
                  <p className="mt-1 text-[0.875rem] text-ink-2">Deletes the key from this computer. The guardian stops working until you add one again.</p>
                  <Button
                    variant="secondary"
                    size="sm"
                    className="mt-3"
                    pending={update.isPending && update.variables === null}
                    onClick={() => {
                      setSaved(null);
                      update.mutate(null);
                    }}
                  >
                    <Icon name="trash" size={15} />
                    Remove saved key
                  </Button>
                </div>
              ) : null}

              <div className="mt-5 border-t border-line pt-4 text-[0.875rem] text-ink-2">
                <h3 className="font-medium text-ink">Where it is stored</h3>
                <ul className="mt-2 list-disc space-y-1.5 pl-5">
                  <li>
                    In <code>secrets.json</code> inside your Kestrix config folder (<code>~/.config/kestrix</code> on macOS and Linux,{" "}
                    <code>%APPDATA%\kestrix</code> on Windows). The file is readable only by your user account.
                  </li>
                  <li>
                    Or set the <code>ANTHROPIC_API_KEY</code> environment variable before running <code>kestrix dashboard</code>. It takes
                    precedence over the saved file, and removing the saved key here does not unset it.
                  </li>
                </ul>
              </div>
            </section>
          )}
        </div>
      </div>
    </>
  );
}
