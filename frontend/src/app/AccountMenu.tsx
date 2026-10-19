// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation } from "@tanstack/react-query";
import { useId, useState } from "react";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorState, Spinner } from "../components/ui";
import { providerName } from "../features/auth/providers";
import { api } from "../lib/api";
import { browser } from "../lib/browser";
import { useMe } from "../lib/queries";
import { landingPath } from "./paths";

const CONFIRM_WORD = "DELETE";

export function DeleteAccountDialog({ onClose, onDeleted }: { onClose: () => void; onDeleted: () => void }) {
  const [typed, setTyped] = useState("");
  const inputId = useId();
  const remove = useMutation({ mutationFn: api.deleteAccount, onSuccess: onDeleted });
  const ready = typed === CONFIRM_WORD && !remove.isPending;
  return (
    <Dialog title="Delete your account?" onClose={onClose}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) remove.mutate();
        }}
        className="grid gap-4"
      >
        <p className="text-ink-2">
          This removes your Kestrix account and signs you out everywhere, right away. It cannot be undone. Your Google
          or GitHub account is not affected.
        </p>
        <div className="grid gap-1.5">
          <label htmlFor={inputId} className="font-medium">
            Type {CONFIRM_WORD} to confirm
          </label>
          <input
            id={inputId}
            className="field font-mono"
            autoComplete="off"
            spellCheck={false}
            value={typed}
            onChange={(event) => {
              setTyped(event.target.value);
            }}
          />
        </div>
        {remove.isError ? <ErrorState error={remove.error} /> : null}
        <div className="flex flex-wrap justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-danger" disabled={!ready}>
            {remove.isPending ? <Spinner /> : null}
            Delete account
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/** Hosted mode: who is signed in, with sign-out and account deletion. */
export function AccountMenu() {
  const me = useMe();
  const [confirming, setConfirming] = useState(false);

  function leave(search: string) {
    browser.assign(`${landingPath()}${search}`);
  }

  const signOut = useMutation({
    mutationFn: api.logout,
    onSuccess: () => {
      leave("");
    },
  });

  const user = me.data?.signed_in ? me.data.user : null;
  if (!user) return null;
  return (
    <section aria-label="Account" className="space-y-3 text-[0.8125rem]">
      <div className="flex items-center gap-2.5">
        <span
          className="flex size-9 flex-none items-center justify-center rounded-full bg-[linear-gradient(135deg,var(--btn-a),var(--btn-b))] text-[0.9375rem] font-bold text-white"
          aria-hidden="true"
        >
          {(user.display_name || user.email).slice(0, 1).toUpperCase()}
        </span>
        <div className="min-w-0">
          <p className="truncate font-semibold text-ink">{user.display_name || user.email}</p>
          <p className="truncate text-ink-2">{user.email}</p>
          <p className="text-ink-3">Signed in with {providerName[user.provider]}</p>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          disabled={signOut.isPending}
          onClick={() => {
            signOut.mutate();
          }}
        >
          <Icon name="arrowLeft" size={14} />
          Sign out
        </button>
        <button
          type="button"
          className="btn btn-ghost btn-sm text-crit"
          onClick={() => {
            setConfirming(true);
          }}
        >
          Delete account
        </button>
      </div>
      {signOut.isError ? <ErrorState error={signOut.error} /> : null}
      {confirming ? (
        <DeleteAccountDialog
          onClose={() => {
            setConfirming(false);
          }}
          onDeleted={() => {
            leave("?account=deleted");
          }}
        />
      ) : null}
    </section>
  );
}
