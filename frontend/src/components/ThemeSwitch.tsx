// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId } from "react";
import { setTheme, useTheme, type ThemeChoice } from "../lib/theme";
import { Icon, type IconName } from "./Icon";
import { cx } from "./ui";

const options: { value: ThemeChoice; label: string; icon: IconName }[] = [
  { value: "system", label: "System", icon: "monitor" },
  { value: "light", label: "Light", icon: "sun" },
  { value: "dark", label: "Dark", icon: "moon" },
];

/** Three-way theme choice as a native radio group (arrow keys work for free). */
export function ThemeSwitch() {
  const theme = useTheme();
  const name = useId();
  return (
    <fieldset>
      <legend className="mb-2 text-[0.8125rem] font-medium text-ink-2">Theme</legend>
      <div className="grid grid-cols-3 gap-1 rounded-lg border border-line bg-bg p-1">
        {options.map((option) => (
          <label
            key={option.value}
            className={cx(
              "relative flex min-h-8 cursor-pointer items-center justify-center gap-1.5 rounded-md text-xs font-medium transition-colors duration-150 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-(--focus)",
              theme === option.value ? "bg-surface text-ink shadow-panel" : "text-ink-2 hover:text-ink",
            )}
          >
            <input
              type="radio"
              name={name}
              value={option.value}
              checked={theme === option.value}
              onChange={() => {
                setTheme(option.value);
              }}
              className="sr-only"
            />
            <Icon name={option.icon} size={14} />
            {option.label}
          </label>
        ))}
      </div>
    </fieldset>
  );
}
