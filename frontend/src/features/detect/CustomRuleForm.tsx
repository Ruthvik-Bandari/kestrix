// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation } from "@tanstack/react-query";
import { useState, type SubmitEvent } from "react";
import { FileButton } from "../../components/FileButton";
import { Icon } from "../../components/Icon";
import { Button, Disclosure, ErrorState, Field, Panel, Spinner } from "../../components/ui";
import { api } from "../../lib/api";
import { formatBytes } from "../../lib/format";
import type { RunBody } from "../../lib/types";

const MAX_RULE = 100 * 1024;
const MAX_FIXTURES = 25 * 1024 * 1024;
/** The server refuses /api/detect/run bodies over 60 MB before reading them. */
const MAX_BODY = 60 * 1024 * 1024;

const RULE_PLACEHOLDER = `title: Execution from user Temp directory
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|contains: \\AppData\\Local\\Temp\\
  condition: selection`;

const MAPPING_PLACEHOLDER = `schema_version: 1
name: my-ecs
fields:
  Image: process.executable
  CommandLine: process.command_line`;

const JSONL_PLACEHOLDER = `{"event_id": "e1", "label": "malicious", "scenario_id": "S-1", "data": {"process": {"executable": "C:\\\\Users\\\\a\\\\AppData\\\\Local\\\\Temp\\\\x.exe"}}}
{"event_id": "e2", "label": "benign", "data": {"process": {"executable": "C:\\\\Windows\\\\notepad.exe"}}}`;

type Key = "rule" | "mapping" | "development" | "validation" | "healthy_rule" | "healthy_mapping";

interface Spec {
  key: Key;
  label: string;
  hint: string;
  placeholder?: string;
  accept: string;
  max: number;
  rows: number;
  required: boolean;
}

const specs: Record<Key, Spec> = {
  rule: {
    key: "rule",
    label: "Sigma rule",
    hint: "YAML. Process-creation rules with equals, contains, startswith, endswith, |all, lists of field maps and 1 of / all of are supported.",
    placeholder: RULE_PLACEHOLDER,
    accept: ".yml,.yaml,text/yaml",
    max: MAX_RULE,
    rows: 10,
    required: true,
  },
  mapping: {
    key: "mapping",
    label: "Field mapping",
    hint: "YAML that maps each Sigma field to the field name in your log index.",
    placeholder: MAPPING_PLACEHOLDER,
    accept: ".yml,.yaml,text/yaml",
    max: MAX_RULE,
    rows: 7,
    required: true,
  },
  development: {
    key: "development",
    label: "Development events (JSONL)",
    hint: "One labeled event per line: event_id, label (malicious, benign or unknown), optional scenario_id, and data.",
    placeholder: JSONL_PLACEHOLDER,
    accept: ".jsonl,.ndjson,.json,application/x-ndjson",
    max: MAX_FIXTURES,
    rows: 6,
    required: true,
  },
  validation: {
    key: "validation",
    label: "Validation events (JSONL, recommended)",
    hint: "A separate labeled set used to accept or reject the fix. Without it a repair is only provisional.",
    accept: ".jsonl,.ndjson,.json,application/x-ndjson",
    max: MAX_FIXTURES,
    rows: 4,
    required: false,
  },
  healthy_rule: {
    key: "healthy_rule",
    label: "Healthy reference rule (optional)",
    hint: "A known-good version of the rule. Its false alarms on validation events set the baseline a fix must not exceed.",
    accept: ".yml,.yaml,text/yaml",
    max: MAX_RULE,
    rows: 5,
    required: false,
  },
  healthy_mapping: {
    key: "healthy_mapping",
    label: "Healthy reference mapping (optional)",
    hint: "A known-good mapping to pair with the healthy rule.",
    accept: ".yml,.yaml,text/yaml",
    max: MAX_RULE,
    rows: 5,
    required: false,
  },
};

const empty: Record<Key, string> = {
  rule: "",
  mapping: "",
  development: "",
  validation: "",
  healthy_rule: "",
  healthy_mapping: "",
};

function TextInput({
  spec,
  value,
  error,
  onChange,
  onError,
}: {
  spec: Spec;
  value: string;
  error: string | null;
  onChange: (value: string) => void;
  onError: (message: string | null) => void;
}) {
  const id = `detect-${spec.key}`;
  const describedBy = [`${id}-hint`, error ? `${id}-error` : null].filter(Boolean).join(" ");
  return (
    <Field
      htmlFor={id}
      label={spec.label}
      hint={spec.hint}
      error={error}
    >
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <FileButton
          label="Load file"
          accept={spec.accept}
          onFile={(file) => {
            if (file.size > spec.max) {
              onError(`${file.name} is ${formatBytes(file.size)}; the limit is ${formatBytes(spec.max)}.`);
              return;
            }
            void file.text().then((text) => {
              onError(null);
              onChange(text);
            });
          }}
        />
        {value ? <span className="text-[0.8125rem] text-ink-3">{formatBytes(new Blob([value]).size)}</span> : null}
      </div>
      <textarea
        id={id}
        className="field"
        rows={spec.rows}
        spellCheck={false}
        autoComplete="off"
        value={value}
        placeholder={spec.placeholder}
        required={spec.required}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      />
    </Field>
  );
}

export function CustomRuleForm({
  onRun,
  running,
}: {
  onRun: (body: RunBody) => void;
  running: boolean;
}) {
  const [values, setValues] = useState(empty);
  const [errors, setErrors] = useState<Partial<Record<Key, string | null>>>({});
  const parse = useMutation({ mutationFn: api.parseRule });

  const set = (key: Key) => (value: string) => {
    setValues((current) => ({ ...current, [key]: value }));
    setErrors((current) => ({ ...current, [key]: null }));
    if (key === "rule") parse.reset();
  };
  const setError = (key: Key) => (message: string | null) => {
    setErrors((current) => ({ ...current, [key]: message }));
  };

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const missing: Partial<Record<Key, string>> = {};
    for (const key of ["rule", "mapping", "development"] as const) {
      if (!values[key].trim()) missing[key] = `${specs[key].label} is required.`;
    }
    if (Object.keys(missing).length) {
      setErrors((current) => ({ ...current, ...missing }));
      document.getElementById(`detect-${Object.keys(missing)[0] ?? "rule"}`)?.focus();
      return;
    }
    const oversized = (Object.keys(specs) as Key[]).find((key) => new Blob([values[key]]).size > specs[key].max);
    if (oversized) {
      setErrors((current) => ({ ...current, [oversized]: `This is larger than the ${formatBytes(specs[oversized].max)} limit.` }));
      document.getElementById(`detect-${oversized}`)?.focus();
      return;
    }
    const total = new Blob(Object.values(values)).size;
    if (total > MAX_BODY) {
      setErrors((current) => ({
        ...current,
        development: `All inputs together are ${formatBytes(total)}; the server accepts up to ${formatBytes(MAX_BODY)} per run.`,
      }));
      document.getElementById("detect-development")?.focus();
      return;
    }
    const optional = (text: string) => (text.trim() ? text : null);
    onRun({
      rule: values.rule,
      mapping: values.mapping,
      development: values.development,
      validation: optional(values.validation),
      healthy_rule: optional(values.healthy_rule),
      healthy_mapping: optional(values.healthy_mapping),
    });
  }

  const input = (key: Key) => (
    <TextInput spec={specs[key]} value={values[key]} error={errors[key] ?? null} onChange={set(key)} onError={setError(key)} />
  );

  return (
    <form onSubmit={submit} noValidate className="space-y-6" aria-label="Repair your own rule">
      <p className="max-w-[68ch] text-ink-2">
        Paste or load your own rule, field mapping and labeled events. They are sent only to the Kestrix server on
        this computer and replayed on the local engine.
      </p>
      <div className="grid items-start gap-6 min-[68.75rem]:grid-cols-2">
        <Panel as="section" className="space-y-3">
          {input("rule")}
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              disabled={!values.rule.trim() || parse.isPending}
              onClick={() => {
                parse.mutate(values.rule);
              }}
            >
              {parse.isPending ? <Spinner /> : <Icon name="check" size={15} />}
              Check rule
            </Button>
          </div>
          <div aria-live="polite">
            {parse.isError ? <ErrorState error={parse.error} /> : null}
            {parse.data ? (
              <div className="rounded-lg bg-ok-bg px-4 py-3 text-[0.875rem]">
                <p className="font-medium text-ok">The rule parses: “{parse.data.title}”</p>
                <dl className="mt-1 grid gap-x-4 gap-y-0.5 text-ink sm:grid-cols-[auto_1fr]">
                  <dt className="text-ink-2">Fields</dt>
                  <dd className="font-mono break-all">{parse.data.fields.join(", ")}</dd>
                  <dt className="text-ink-2">Condition</dt>
                  <dd className="font-mono break-all">{parse.data.condition}</dd>
                </dl>
              </div>
            ) : null}
          </div>
        </Panel>
        <Panel as="section">{input("mapping")}</Panel>
      </div>
      <div className="grid items-start gap-6 min-[68.75rem]:grid-cols-2">
        <Panel as="section">{input("development")}</Panel>
        <Panel as="section">{input("validation")}</Panel>
      </div>
      <Disclosure summary="Advanced: healthy reference">
        <div className="grid gap-6 min-[68.75rem]:grid-cols-2">
          {input("healthy_rule")}
          {input("healthy_mapping")}
        </div>
      </Disclosure>
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" icon="play" pending={running} pendingLabel="Running repair…">
          Diagnose and repair
        </Button>
        <Button
          variant="ghost"
          onClick={() => {
            setValues(empty);
            setErrors({});
            parse.reset();
          }}
        >
          Clear
        </Button>
      </div>
    </form>
  );
}
