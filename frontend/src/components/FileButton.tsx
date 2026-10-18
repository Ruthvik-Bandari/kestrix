// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId } from "react";
import { Icon } from "./Icon";

/** A native file input presented as a secondary button. Keyboard and screen-reader friendly. */
export function FileButton({
  label,
  accept,
  onFile,
}: {
  label: string;
  accept?: string;
  onFile: (file: File) => void;
}) {
  const id = useId();
  return (
    <label
      htmlFor={id}
      className="btn btn-secondary btn-sm relative has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-(--focus)"
    >
      <Icon name="upload" size={15} />
      {label}
      <input
        id={id}
        type="file"
        className="sr-only"
        {...(accept ? { accept } : {})}
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) onFile(file);
          event.target.value = "";
        }}
      />
    </label>
  );
}
