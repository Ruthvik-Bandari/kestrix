# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Rules for GitHub Actions workflows (``.github/workflows/*.yml``) and composite actions (``action.yml``).

The file is read with the bounded YAML subset reader in ``yaml_lite.py``; nothing in it is run or expanded. The rules follow
GitHub's security-hardening guide for Actions.

- ``gha.pr_target.checkout_head``: a ``pull_request_target`` or ``workflow_run`` workflow that checks out the pull request's
  head (``actions/checkout`` with a head ``ref`` or ``repository``, or ``gh pr checkout`` / ``git checkout`` of a head ref);
- ``gha.injection.untrusted_context``: an untrusted ``github.event.*`` field or ``github.head_ref`` written as ``${{ ... }}``
  inside a ``run:`` script (CWE-78) or an ``actions/github-script`` ``script:`` (CWE-94). Passing the value through ``env:`` and
  reading it as ``$NAME`` is the fix and is not reported;
- ``gha.action.unpinned``: a third-party ``uses:`` that is not pinned to a full 40-character commit SHA. First-party actions
  (``actions/*`` and ``github/*``), local actions (``./``) and ``docker://`` images are not reported;
- ``gha.permissions.write_all`` and ``gha.permissions.missing``: ``permissions: write-all``, and a workflow that uses secrets
  but sets ``permissions`` neither at the top nor on every job;
- ``gha.secrets.echoed``: ``echo`` or ``printf`` of ``${{ secrets.NAME }}`` straight to the log.
"""

from __future__ import annotations

import re

from .models import Confidence, Severity, SkipReason, clip_snippet
from .registry import Hit
from .shell_rules import ALL_CHECKS, logical_lines, shell_hits
from .yaml_lite import Map, Node, Scalar, Seq, YamlError, iter_scalars, load_documents

MAX_WORKFLOW_BYTES = 512 * 1024
_FIRST_PARTY = frozenset({"actions", "github"})
_SHA = re.compile(r"^[0-9a-f]{40}$")
_USES = re.compile(r"^(?P<owner>[^/\s@]+)/(?P<repo>[^/\s@]+)(?P<path>/[^\s@]*)?@(?P<ref>\S+)$")
_EXPRESSION = re.compile(r"\$\{\{(?P<body>.*?)\}\}", re.DOTALL)
_INDEX = r"(?:\[[^\]]*\]|\.\*)?"
_PERSON = r"(?:email|name)"
_UNTRUSTED = re.compile(
    r"(?<![\w.])(?:github\.head_ref|github\.event\.(?:"
    r"issue\.(?:title|body)"
    r"|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))"
    r"|comment\.body|review\.body|review_comment\.body"
    rf"|pages{_INDEX}\.page_name"
    rf"|(?:commits{_INDEX}|head_commit)\.(?:message|author\.{_PERSON}|committer\.{_PERSON})"
    rf"|workflow_run\.(?:head_branch|head_commit\.(?:message|author\.{_PERSON}|committer\.{_PERSON})|head_repository\.description"
    rf"|pull_requests{_INDEX}\.head\.ref)"
    r"|discussion\.(?:title|body)"
    r"|release\.(?:name|body)"
    r"))(?![\w])"
)
_BOOLEAN_EXPRESSION = re.compile(r"(?:\b(?:contains|startsWith|endsWith)\s*\(|==|!=)")
_HEAD_REF = re.compile(
    r"github\.head_ref|github\.event\.pull_request\.(?:head\.(?:sha|ref|repo)|merge_commit_sha)|refs/pull/"
    r"|github\.event\.workflow_run\.head_(?:sha|branch|repository)|github\.event\.workflow_run\.pull_requests"
)
_CHECKOUT_COMMAND = re.compile(r"\b(?:gh\s+pr\s+checkout|git\s+(?:checkout|fetch|switch|pull)\b[^\n;&|]*)")
_PRIVILEGED_TRIGGERS = frozenset({"pull_request_target", "workflow_run"})
_SECRET = re.compile(r"\bsecrets\.(?!GITHUB_TOKEN\b)\w+", re.IGNORECASE)
_ECHO = re.compile(r"(?:^|[;&|`{]|(?<![<$])\(|\b(?:then|do|else)\b)\s*(?:echo|printf)\b(?P<args>[^\n]*)$")


def is_workflow(rel: str) -> bool:
    """A workflow file, a composite action under ``.github/actions/`` or an ``action.yml`` at some path."""
    parts = rel.split("/")
    name = parts[-1].lower()
    if not name.endswith((".yml", ".yaml")):
        return False
    if len(parts) >= 3 and parts[-2] == "workflows" and parts[-3] == ".github":
        return True
    return name in ("action.yml", "action.yaml")


class _Workflow:
    def __init__(self, text: str) -> None:
        self.lines = text.splitlines()
        self.hits: list[Hit] = []

    def hit(
        self,
        rule_id: str,
        line: int,
        message: str,
        *,
        cwe: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
    ) -> None:
        snippet = clip_snippet(self.lines[line - 1]) if 1 <= line <= len(self.lines) else ""
        self.hits.append(
            Hit(
                rule_id=rule_id,
                line=line,
                column=1,
                end_line=line,
                message=message,
                snippet=snippet,
                cwe=cwe,
                severity=severity,
                confidence=confidence,
            )
        )


def _triggers(node: Node | None) -> set[str]:
    if isinstance(node, Scalar):
        return {node.value}
    if isinstance(node, Seq):
        return {item.value for item in node.items if isinstance(item, Scalar)}
    if isinstance(node, Map):
        return {key for key, _, _ in node.entries}
    return set()


def _steps(document: Map) -> list[tuple[Map, Map | None]]:
    """(step, owning job) for every step of the workflow's jobs and of a composite action."""
    out: list[tuple[Map, Map | None]] = []
    jobs = document.get("jobs")
    if isinstance(jobs, Map):
        for _, _, job in jobs.entries:
            if isinstance(job, Map) and isinstance(steps := job.get("steps"), Seq):
                out.extend((step, job) for step in steps.items if isinstance(step, Map))
    runs = document.get("runs")
    if isinstance(runs, Map) and isinstance(steps := runs.get("steps"), Seq):
        out.extend((step, None) for step in steps.items if isinstance(step, Map))
    return out


def _script_line(scalar: Scalar, offset: int, text: str) -> int:
    """Source line of character ``offset`` in a ``run:`` or ``script:`` value (block lines map one to one)."""
    return scalar.line + text.count("\n", 0, offset) if scalar.block else scalar.line


def _check_pull_request_target(flow: _Workflow, document: Map) -> None:
    if not _triggers(document.get("on")) & _PRIVILEGED_TRIGGERS:
        return
    for step, _ in _steps(document):
        uses = step.scalar("uses")
        with_ = step.get("with")
        if uses is not None and uses.value.lower().startswith("actions/checkout") and isinstance(with_, Map):
            for key in ("ref", "repository"):
                value = with_.scalar(key)
                if value is not None and _HEAD_REF.search(value.value):
                    flow.hit(
                        "gha.pr_target.checkout_head",
                        with_.key_line(key),
                        "This workflow runs with the base repository's token and secrets, and it checks out code from the "
                        "pull request's head, so a pull request can run its own code with them.",
                    )
        run = step.scalar("run")
        if run is not None:
            for match in _CHECKOUT_COMMAND.finditer(run.value):
                if "gh pr checkout" in match.group(0) or _HEAD_REF.search(match.group(0)):
                    flow.hit(
                        "gha.pr_target.checkout_head",
                        _script_line(run, match.start(), run.value),
                        "This workflow runs with the base repository's token and secrets, and a command here fetches the "
                        "pull request's head, so a pull request can run its own code with them.",
                    )
                    break


def _check_injection(flow: _Workflow, document: Map) -> None:
    for step, _ in _steps(document):
        targets: list[tuple[Scalar, str]] = []
        if (run := step.scalar("run")) is not None:
            targets.append((run, "CWE-78"))
        uses, with_ = step.scalar("uses"), step.get("with")
        script = with_.scalar("script") if isinstance(with_, Map) else None
        if uses is not None and uses.value.lower().startswith("actions/github-script") and script is not None:
            targets.append((script, "CWE-94"))
        for scalar, cwe in targets:
            for match in _EXPRESSION.finditer(scalar.value):
                body = match.group("body")
                found = _UNTRUSTED.search(body)
                if found is None or _BOOLEAN_EXPRESSION.search(body):
                    continue
                where = "a shell command" if cwe == "CWE-78" else "a script"
                flow.hit(
                    "gha.injection.untrusted_context",
                    _script_line(scalar, match.start(), scalar.value),
                    f"${{{{ {found.group(0)} }}}} is written into {where}, so whoever controls that field "
                    "(a pull request title, a branch name, a comment) controls the text GitHub substitutes.",
                    cwe=cwe,
                )


def _check_uses(flow: _Workflow, document: Map) -> None:
    jobs = document.get("jobs")
    nodes: list[Map] = [step for step, _ in _steps(document)]
    if isinstance(jobs, Map):
        nodes.extend(job for _, _, job in jobs.entries if isinstance(job, Map))
    for node in nodes:
        uses = node.scalar("uses")
        if uses is None:
            continue
        match = _USES.match(uses.value)
        if match is None or match.group("owner").lower() in _FIRST_PARTY or _SHA.match(match.group("ref")):
            continue
        flow.hit(
            "gha.action.unpinned",
            uses.line,
            f"{match.group('owner')}/{match.group('repo')} is pinned to {match.group('ref')!r}, a tag or branch its owner can "
            "move, not a commit SHA.",
        )


def _uses_secrets(document: Map) -> bool:
    for scalar in iter_scalars(document):
        if _SECRET.search(scalar.value):
            return True
    jobs = document.get("jobs")
    if isinstance(jobs, Map):
        for _, _, job in jobs.entries:
            if (
                isinstance(job, Map)
                and (inherited := job.scalar("secrets")) is not None
                and inherited.value == "inherit"
            ):
                return True
    return False


def _check_permissions(flow: _Workflow, document: Map) -> None:
    top = document.scalar("permissions")
    if top is not None and top.value == "write-all":
        flow.hit(
            "gha.permissions.write_all",
            document.key_line("permissions"),
            "permissions: write-all gives every job's token write access to the whole repository.",
        )
    jobs = document.get("jobs")
    if not isinstance(jobs, Map):
        return
    unrestricted: list[int] = []
    for name, line, job in jobs.entries:
        if not isinstance(job, Map):
            continue
        scalar = job.scalar("permissions")
        if scalar is not None and scalar.value == "write-all":
            flow.hit(
                "gha.permissions.write_all",
                job.key_line("permissions"),
                f"permissions: write-all gives job {name!r} write access to the whole repository.",
            )
        if job.get("permissions") is None:
            unrestricted.append(line)
    if document.get("permissions") is None and unrestricted and _uses_secrets(document):
        flow.hit(
            "gha.permissions.missing",
            document.key_line("jobs"),
            "The workflow uses secrets but sets no permissions at the top or on every job, so the GITHUB_TOKEN gets the "
            "repository's default permissions (read and write for repositories that kept the old default).",
        )


def _check_secret_echo(flow: _Workflow, document: Map) -> None:
    for step, _ in _steps(document):
        run = step.scalar("run")
        if run is None or "secrets." not in run.value:
            continue
        for logical in logical_lines(run.value, run.line):
            text = logical.text
            if "::add-mask::" in text:
                continue
            match = _ECHO.search(text)
            if match is None:
                continue
            args = match.group("args")
            if not _SECRET.search(args) or re.search(r"[|>]", args.replace("${{", "").replace("}}", "")):
                continue
            secret_expressions = [
                m.group("body") for m in _EXPRESSION.finditer(args) if _SECRET.search(m.group("body"))
            ]
            if secret_expressions and all(_BOOLEAN_EXPRESSION.search(body) for body in secret_expressions):
                continue  # a test such as ${{ secrets.X != '' }} prints true or false, not the secret
            line, _ = logical.at(match.start())
            flow.hit(
                "gha.secrets.echoed",
                line,
                "A secret is written to the job log. GitHub masks exact matches of the value, but a changed form "
                "(base64, a substring, a URL-encoded copy) is not masked.",
            )


def _check_run_shell(flow: _Workflow, document: Map) -> None:
    for step, _ in _steps(document):
        run = step.scalar("run")
        if run is not None:
            flow.hits.extend(shell_hits(run.value, run.line, checks=ALL_CHECKS))


def check_workflow(text: str, rel: str) -> list[Hit] | SkipReason:
    """Rule hits for one workflow or composite action file, or why it could not be analyzed."""
    if len(text.encode("utf-8", "replace")) > MAX_WORKFLOW_BYTES:
        return "too_large"
    try:
        documents = load_documents(text)
    except YamlError as exc:
        return exc.reason
    except RecursionError:
        return "too_complex"
    flow = _Workflow(text)
    for document in documents:
        if not isinstance(document, Map):
            continue
        _check_pull_request_target(flow, document)
        _check_injection(flow, document)
        _check_uses(flow, document)
        _check_permissions(flow, document)
        _check_secret_echo(flow, document)
        _check_run_shell(flow, document)
    return flow.hits
