// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Link } from "react-router";
import { PRIVACY_PATH } from "../app/paths";
import { isHosted } from "../lib/mode";
import { Icon } from "./Icon";
import { cx } from "./ui";

/**
 * The one line a tool shows before its check runs: where the input goes. Retention details live
 * on the Recent results and Settings pages and in the privacy notice, which the hosted line links.
 */
export function DataNote({ subject, className }: { subject: string; className?: string }) {
  return (
    <p className={cx("flex gap-2 text-[0.875rem] text-ink-2", className)}>
      <Icon name="lock" size={16} className="mt-0.5 flex-none text-ink-3" />
      {isHosted() ? (
        <span>
          {subject} is checked on Kestrix&apos;s server and never stored; only the report is kept, in Recent results.{" "}
          <Link className="link" to={PRIVACY_PATH}>
            Privacy notice
          </Link>
        </span>
      ) : (
        <span>{subject} is checked on this computer and never leaves it.</span>
      )}
    </p>
  );
}
