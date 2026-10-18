// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0

const paths = {
  shield: "M12 3 4.5 6v5.5c0 4.6 3.1 8.4 7.5 9.5 4.4-1.1 7.5-4.9 7.5-9.5V6L12 3Z",
  check: "M5 12.5 10 17.5 19 7",
  checkCircle: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM8 12.5l2.7 2.7L16.5 9.5",
  x: "M6 6l12 12M18 6 6 18",
  xCircle: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM9 9l6 6M15 9l-6 6",
  alert: "M12 4 2.8 19.5h18.4L12 4ZM12 10v4.5M12 17.2v.3",
  octagon: "M8.3 3h7.4L21 8.3v7.4L15.7 21H8.3L3 15.7V8.3L8.3 3ZM12 7.5v5.5M12 16.2v.3",
  info: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 11v5.5M12 7.8v.3",
  minus: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM8 12h8",
  help: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM9.6 9.4a2.5 2.5 0 0 1 4.8.9c0 1.7-2.4 2.2-2.4 3.7M12 16.8v.3",
  copy: "M9 9h10v11H9zM5 15V4h10",
  download: "M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19.5h14",
  upload: "M12 15V4M7.5 8.5 12 4l4.5 4.5M5 19.5h14",
  file: "M14 3H6.5v18h11V6.5L14 3Zm0 0v3.5h3.5",
  globe: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM3.5 9h17M3.5 15h17M12 3c-2.4 2.5-3.5 5.5-3.5 9s1.1 6.5 3.5 9M12 3c2.4 2.5 3.5 5.5 3.5 9s-1.1 6.5-3.5 9",
  key: "M14.5 9.5a4 4 0 1 1-8 0 4 4 0 0 1 8 0ZM13.6 12.4 20 18.8V21h-2.5v-1.8h-1.8v-1.8l-4.4-4.4",
  wrench: "M14.7 6.3a4 4 0 0 0 5 5L21 13l-8 8-8-8 1.7-1.3M14.7 6.3 11 10l3 3 3.7-3.7M14.7 6.3a4 4 0 0 1 5-3l-2.5 2.5.5 2 2 .5 2.5-2.5a4 4 0 0 1-3 5",
  sliders: "M4 7h10M18 7h2M4 17h4M12 17h8M16 5v4M10 15v4",
  menu: "M4 7h16M4 12h16M4 17h16",
  sun: "M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4",
  moon: "M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z",
  monitor: "M3.5 5h17v11h-17zM9 20h6M12 16v4",
  arrowRight: "M5 12h14M13 6l6 6-6 6",
  arrowLeft: "M19 12H5M11 6l-6 6 6 6",
  chevronDown: "M6 9l6 6 6-6",
  play: "M8 5.5v13l10.5-6.5L8 5.5Z",
  lock: "M6.5 10.5h11v10h-11zM8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3",
  pin: "M12 21s6.5-5.8 6.5-11a6.5 6.5 0 0 0-13 0c0 5.2 6.5 11 6.5 11ZM12 12.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z",
  bitcoin: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM9.5 7.5h3.8a2 2 0 0 1 0 4H9.5h4.3a2.2 2.2 0 0 1 0 4.5H9.5v-8.5ZM11 6v1.5M11 16v2M13 6v1.5M13 16v2",
  mail: "M3.5 6h17v12h-17zM3.5 6.5 12 13l8.5-6.5",
  search: "M10.5 17.5a7 7 0 1 0 0-14 7 7 0 0 0 0 14ZM15.5 15.5 21 21",
  sparkle: "M12 3.5 13.8 10.2 20.5 12l-6.7 1.8L12 20.5l-1.8-6.7L3.5 12l6.7-1.8L12 3.5Z",
  external: "M14 4h6v6M20 4l-9 9M18 14v6H4V6h6",
} as const;

export type IconName = keyof typeof paths;

interface IconProps {
  name: IconName;
  size?: number;
  className?: string;
  /** When set, the icon is announced; otherwise it is decorative. */
  label?: string;
}

export function Icon({ name, size = 18, className, label }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      focusable="false"
    >
      <path d={paths[name]} />
    </svg>
  );
}
