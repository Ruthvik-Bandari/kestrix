import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { ApiError } from "../lib/api";
import { downloadText } from "../lib/download";
import { Icon, type IconName } from "./Icon";
import { tones, type Tone } from "./tone";

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

// Layout ---------------------------------------------------------------------

export function PageHeader({ title, lede, aside }: { title: string; lede: ReactNode; aside?: ReactNode }) {
  return (
    <header className="mb-8 flex flex-col gap-4 border-b border-line pb-6 md:flex-row md:items-end md:justify-between">
      <div className="max-w-[68ch]">
        <h1 className="text-[1.75rem] leading-tight font-semibold tracking-[-0.015em]">{title}</h1>
        <p className="mt-2 text-ink-2">{lede}</p>
      </div>
      {aside ? <div className="flex flex-wrap items-center gap-2">{aside}</div> : null}
    </header>
  );
}

export function SectionTitle({ children, id, aside }: { children: ReactNode; id?: string; aside?: ReactNode }) {
  return (
    <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
      <h2 id={id} className="text-lg font-semibold tracking-[-0.01em]">
        {children}
      </h2>
      {aside}
    </div>
  );
}

// Status ---------------------------------------------------------------------

/** Compact status label: icon + text, tinted. Never color alone. */
export function Badge({ tone, children, icon }: { tone: Tone; children: ReactNode; icon?: IconName | null }) {
  const style = tones[tone];
  const glyph = icon === null ? null : (icon ?? style.icon);
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[0.8125rem] leading-5 font-medium whitespace-nowrap",
        style.soft,
      )}
    >
      {glyph ? <Icon name={glyph} size={14} /> : null}
      {children}
    </span>
  );
}

/** Status pill with a live dot, used for system state (engine, AI key). */
export function StatusPill({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1 text-[0.8125rem] font-medium text-ink">
      <span className={cx("size-2 rounded-full", tones[tone].mark)} aria-hidden="true" />
      {children}
    </span>
  );
}

/**
 * The verdict line: every result opens with a plain-language headline in its tone,
 * then supporting copy. Technical detail lives further down, one click deeper.
 */
export function Verdict({
  tone,
  title,
  children,
  icon,
  titleId,
}: {
  tone: Tone;
  title: ReactNode;
  children?: ReactNode;
  icon?: IconName;
  titleId?: string;
}) {
  const style = tones[tone];
  return (
    <div className={cx("flex gap-3 rounded-xl px-4 py-4 sm:px-5", style.soft)}>
      <Icon name={icon ?? style.icon} size={22} className="mt-0.5 flex-none" />
      <div className="min-w-0 text-ink">
        <p id={titleId} className={cx("text-base leading-snug font-semibold", style.text)}>
          {title}
        </p>
        {children ? <div className="mt-1 text-[0.9375rem] text-ink-2">{children}</div> : null}
      </div>
    </div>
  );
}

// Feedback -------------------------------------------------------------------

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2" role={label ? "status" : undefined}>
      <span
        className="size-4 flex-none rounded-full border-2 border-current border-r-transparent [animation:spin_700ms_linear_infinite]"
        aria-hidden="true"
      />
      {label ? <span>{label}</span> : null}
    </span>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("animate-pulse rounded-md bg-inset", className)} aria-hidden="true" />;
}

const errorTitles: Record<string, string> = {
  network_error: "Can't reach the Kestrix server",
  engine_unavailable: "The detection engine isn't running",
  engine_error: "The detection engine reported an error",
  ai_key_missing: "An Anthropic API key is needed",
  upstream_error: "An outside service didn't answer properly",
  target_unreachable: "Couldn't reach that address",
  target_not_allowed: "That address isn't allowed",
  input_too_large: "That input is too large",
  cross_site_request: "The server refused a request from another website",
  host_not_allowed: "The server only answers local requests",
  invalid_url: "That doesn't look like a valid URL",
  invalid_request: "Some input needs fixing",
  invalid_input: "Some input needs fixing",
};

function errorTitle(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.reason in errorTitles) return errorTitles[error.reason] ?? "";
    if (error.status === 413) return errorTitles.input_too_large ?? "";
    if (error.status === 403) return "The server refused this request";
    if (error.reason.startsWith("unsupported") || error.reason.startsWith("invalid") || error.reason.startsWith("malformed"))
      return "Some input needs fixing";
  }
  return "Something went wrong";
}

const MIB = 1024 * 1024;

function errorDetail(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 413 || error.reason === "input_too_large") {
      const bytes = /exceeds (\d+) bytes/.exec(error.detail)?.[1];
      if (bytes) return `The request is larger than the ${Math.floor(Number(bytes) / MIB)} MB the server accepts. Use a smaller input.`;
    }
    if (error.reason === "cross_site_request")
      return "Kestrix only accepts actions from its own dashboard. Open the dashboard at the address `kestrix dashboard` printed and try again.";
    return error.detail;
  }
  if (error instanceof Error) return error.message;
  return "An unexpected error occurred.";
}

export function ErrorState({ error, children }: { error: unknown; children?: ReactNode }) {
  const reason = error instanceof ApiError ? error.reason : null;
  return (
    <div role="alert" className="flex gap-3 rounded-xl bg-crit-bg px-4 py-4 sm:px-5">
      <Icon name="xCircle" size={22} className="mt-0.5 flex-none text-crit" />
      <div className="min-w-0">
        <p className="font-semibold text-crit">{errorTitle(error)}</p>
        <p className="mt-1 break-words text-ink">{errorDetail(error)}</p>
        {children ? <div className="mt-2 text-ink-2">{children}</div> : null}
        {reason ? <p className="mt-2 font-mono text-xs text-ink-2">reason: {reason}</p> : null}
      </div>
    </div>
  );
}

// Disclosure, copy, code -------------------------------------------------------

export function Disclosure({
  summary,
  children,
  defaultOpen = false,
}: {
  summary: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  return (
    <details className="group rounded-lg border border-line bg-surface" open={defaultOpen}>
      <summary className="flex min-h-11 list-none items-center gap-2 rounded-lg px-4 py-2 font-medium text-ink select-none hover:bg-inset [&::-webkit-details-marker]:hidden">
        <Icon name="chevronDown" size={16} className="-rotate-90 text-ink-3 transition-transform duration-150 group-open:rotate-0" />
        {summary}
      </summary>
      <div className="border-t border-line px-4 py-4">{children}</div>
    </details>
  );
}

export function CopyButton({ text, label, className }: { text: string; label: string; className?: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<number | undefined>(undefined);
  useEffect(
    () => () => {
      window.clearTimeout(timer.current);
    },
    [],
  );

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      setState("failed");
    }
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      setState("idle");
    }, 2000);
  }

  return (
    <button
      type="button"
      className={cx("btn btn-ghost btn-sm", className)}
      onClick={() => void copy()}
      aria-label={state === "idle" ? label : undefined}
    >
      <Icon name={state === "copied" ? "check" : "copy"} size={15} />
      <span aria-live="polite">{state === "copied" ? "Copied" : state === "failed" ? "Copy failed" : "Copy"}</span>
    </button>
  );
}

export function CodeBlock({ children, label, maxHeight = "24rem" }: { children: string; label: string; maxHeight?: string }) {
  return (
    <pre
      className="overflow-auto rounded-lg bg-inset p-3 leading-relaxed whitespace-pre text-ink"
      style={{ maxHeight }}
      tabIndex={0}
      role="region"
      aria-label={label}
    >
      <code>{children}</code>
    </pre>
  );
}

/** Raw JSON one click deeper, with copy and download. */
export function RawJson({ data, filename, summary = "Raw JSON" }: { data: unknown; filename: string; summary?: string }) {
  const text = JSON.stringify(data, null, 2);
  return (
    <Disclosure summary={summary}>
      <div className="mb-2 flex flex-wrap gap-2">
        <CopyButton text={text} label="Copy JSON" />
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => { downloadText(filename, text); }}>
          <Icon name="download" size={15} />
          Download
        </button>
      </div>
      <CodeBlock label="Raw JSON response">{text}</CodeBlock>
    </Disclosure>
  );
}

// Forms ----------------------------------------------------------------------

export function Field({
  label,
  hint,
  error,
  children,
  htmlFor,
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  htmlFor: string;
  children: ReactNode;
}) {
  return (
    <div>
      <label className="label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {hint ? (
        <p id={`${htmlFor}-hint`} className="hint mt-1.5">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={`${htmlFor}-error`} className="mt-1.5 text-[0.8125rem] font-medium text-crit">
          {error}
        </p>
      ) : null}
    </div>
  );
}

/** Accessible switch built on a native checkbox. */
export function Switch({
  checked,
  onChange,
  label,
  description,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: ReactNode;
  description?: ReactNode;
}) {
  const id = useId();
  return (
    <div className="flex items-start gap-3">
      <span className="relative mt-0.5 inline-flex h-6 w-10 flex-none">
        <input
          id={id}
          type="checkbox"
          role="switch"
          className="peer absolute inset-0 z-10 m-0 cursor-pointer opacity-0"
          checked={checked}
          onChange={(e) => {
            onChange(e.target.checked);
          }}
          aria-describedby={description ? `${id}-desc` : undefined}
        />
        <span
          className="pointer-events-none absolute inset-0 rounded-full border border-line-strong bg-inset transition-colors duration-150 peer-checked:border-accent peer-checked:bg-accent peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-(--focus)"
          aria-hidden="true"
        />
        <span
          className="pointer-events-none absolute top-1 left-1 size-4 rounded-full bg-ink-3 transition-transform duration-150 peer-checked:translate-x-4 peer-checked:bg-on-accent"
          aria-hidden="true"
        />
      </span>
      <div>
        <label htmlFor={id} className="cursor-pointer font-medium text-ink">
          {label}
        </label>
        {description ? (
          <p id={`${id}-desc`} className="hint mt-0.5">
            {description}
          </p>
        ) : null}
      </div>
    </div>
  );
}

