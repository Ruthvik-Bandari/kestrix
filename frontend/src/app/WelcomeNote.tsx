// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Link, useSearchParams } from "react-router";
import { Icon } from "../components/Icon";
import { isHosted } from "../lib/mode";
import { PRIVACY_PATH, TERMS_PATH } from "./paths";

/**
 * Hosted mode: shown once after an account was created through Log in (the server adds
 * `welcome=created` to the return path), since that visitor never saw the Sign up terms checkbox.
 */
export function WelcomeNote() {
  const [params, setParams] = useSearchParams();
  if (!isHosted() || params.get("welcome") !== "created") return null;
  return (
    <div role="status" className="mb-6 flex items-start gap-3 rounded-2xl bg-ok-bg px-4 py-3 shadow-[inset_0_0_0_1px_var(--line)]">
      <Icon name="checkCircle" size={20} className="mt-0.5 flex-none text-ok" />
      <p className="flex-1 text-ink">
        <span className="font-semibold">Welcome, account created.</span> Using Kestrix means you agree to the{" "}
        <Link className="link" to={TERMS_PATH}>
          Terms of use
        </Link>
        ; the{" "}
        <Link className="link" to={PRIVACY_PATH}>
          Privacy notice
        </Link>{" "}
        explains what we keep.
      </p>
      <button
        type="button"
        className="btn btn-ghost btn-sm min-h-10 min-w-10"
        aria-label="Dismiss"
        onClick={() => {
          const rest = new URLSearchParams(params);
          rest.delete("welcome");
          setParams(rest, { replace: true });
        }}
      >
        <Icon name="x" size={16} />
      </button>
    </div>
  );
}
