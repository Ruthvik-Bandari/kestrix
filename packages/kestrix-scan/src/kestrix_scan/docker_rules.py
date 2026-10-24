# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Rules for Dockerfiles and Containerfiles (``Dockerfile``, ``Dockerfile.*``, ``*.Dockerfile``, ``Containerfile``).

The file is read as instructions (comments removed, ``\\`` continuations joined, here-document bodies skipped); nothing is built or
run. ``FROM`` starts a stage, and a ``FROM`` that names an earlier stage inherits that stage's ``USER``.

- ``docker.user.root``: the final stage runs as root, because no ``USER`` is set along its chain or the last one is ``root`` or ``0``;
  ``scratch``, ``nonroot``/``rootless``/``unprivileged`` and ``bitnami/`` images are left alone;
- ``docker.add.remote_url``: ``ADD`` of an ``http://``, ``https://`` or ``ftp://`` URL without ``--checksum``;
- ``docker.run.pipe_to_shell``: ``curl`` or ``wget`` piped into a shell in ``RUN``;
- ``docker.from.latest``: a base image with the ``latest`` tag or no tag and no digest;
- ``docker.env.secret``: ``ENV`` or ``ARG`` with a credential-like name and a literal value (never printed). A value that matches a
  provider pattern is reported by the ``secret.*`` rule instead.

``RUN`` lines also go through ``sh.chmod.world_writable`` and ``sh.eval.variable``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import clip_snippet
from .registry import Hit
from .secrets import detect
from .shell_rules import CHMOD, EVAL, PIPE, SH_RULES, Logical, scan_logical

MAX_INSTRUCTIONS = 20_000
MAX_LINE_CHARS = 16_384
_ROOT_USERS = frozenset({"root", "0", "0:0", "root:root", "0:root", "root:0"})
_NON_ROOT_IMAGE = re.compile(r"(?i)nonroot|rootless|unprivileged|^bitnami/|/bitnami/")
_URL = re.compile(r"""(?:^|[\s\["',])(?:https?|ftp)://""", re.IGNORECASE)
_PAIR = re.compile(r"""([A-Za-z_][A-Za-z0-9_.-]*)=("[^"]*"|'[^']*'|\S*)""")
_CREDENTIAL_NAME = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|token|private[_-]?key|client[_-]?secret)"
)
_NOT_A_SECRET_NAME = re.compile(
    r"(?i)(?:_|-|^)(?:url|uri|path|file|files|dir|name|env|var|header|field|type|id|hash|digest|sha\d*|checksum|length|len|"
    r"count|prefix|pattern|regex|format|endpoint|scope|param|expiry|ttl|ttl_?seconds|enabled|disabled|policy|algorithm|"
    r"alg|mode|location|source|provider|store|manager|helper|cmd|command)(?:_|-|$)"
)
_WEAK_PLACEHOLDER = re.compile(
    r"(?i)changeme|change_me|example|xxxx|placeholder|dummy|sample|fake|your|redacted|todo|replace|insert|<|>|\$|\{|\*\*\*"
)
_WEAK_NON_SECRET = re.compile(r"^(?:(?i:true|false|yes|no|none|null)|\d+|[A-Z][A-Z0-9_]+)$")


@dataclass(slots=True)
class _Stage:
    line: int
    image: str
    alias: str
    parent: int | None  # index of the earlier stage this one is built on
    user: str | None = None
    user_line: int = 0


@dataclass(slots=True)
class _Instruction:
    keyword: str
    rest: str
    start: int  # offset of ``rest`` in ``logical.text``
    logical: Logical


def is_dockerfile(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    return (
        name in ("dockerfile", "containerfile")
        or name.startswith(("dockerfile.", "containerfile."))
        or name.endswith((".dockerfile", ".containerfile"))
    )


def _instructions(text: str) -> list[_Instruction]:
    rows = text.splitlines()
    escape = "\\"
    for row in rows[:8]:  # parser directives are comments at the top of the file
        match = re.match(r"#\s*escape\s*=\s*(\S)\s*$", row, re.IGNORECASE)
        if match:
            escape = match.group(1)
    out: list[_Instruction] = []
    i = 0
    while i < len(rows) and len(out) < MAX_INSTRUCTIONS:
        if not rows[i].strip() or rows[i].lstrip().startswith("#"):
            i += 1
            continue
        parts: list[str] = []
        offsets: list[int] = []
        numbers: list[int] = []
        raws: list[str] = []
        total = 0
        while i < len(rows):
            raw = rows[i]
            i += 1
            if raw.lstrip().startswith("#"):  # a comment line inside a continued instruction
                if parts:
                    continue
                break
            if len(raw) > MAX_LINE_CHARS:
                raw = raw[:MAX_LINE_CHARS]
            stripped = raw.rstrip()
            joined = stripped.endswith(escape)
            piece = stripped[:-1] if joined else stripped
            offsets.append(total)
            numbers.append(i)
            raws.append(raw)
            parts.append(piece)
            total += len(piece) + 1
            if not joined:
                break
        if not parts:
            continue
        logical = Logical(" ".join(parts), offsets, numbers, raws)
        match = re.match(r"\s*([A-Za-z]+)\s*(.*)$", logical.text)
        if match is None:
            continue
        out.append(_Instruction(match.group(1).upper(), match.group(2), match.start(2), logical))
        heredoc = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][\w-]*)\1", logical.text)
        if heredoc is not None and "<<<" not in logical.text:
            tag = heredoc.group(2)
            while i < len(rows) and rows[i].strip() != tag:
                i += 1
            i += 1
    return out


def _hit(rule_id: str, ins: _Instruction, message: str, *, pos: int | None = None, snippet: str | None = None) -> Hit:
    line, raw = ins.logical.at(ins.start if pos is None else pos)
    return Hit(
        rule_id=rule_id,
        line=line,
        column=1,
        end_line=line,
        message=message,
        snippet=clip_snippet(snippet if snippet is not None else raw),
    )


def _image_problem(image: str) -> str | None:
    """'latest' or 'untagged' when the image reference has a mutable tag and no digest, else None."""
    if "@" in image or any(char in image for char in "${<"):
        return None  # a digest, or an ARG or template placeholder
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "untagged"
    return "latest" if last.rsplit(":", 1)[1].lower() == "latest" else None


def _split_assignments(rest: str) -> list[tuple[str, str]]:
    """(name, value) pairs of an ``ENV`` or ``ARG`` argument list, values unquoted."""
    pairs = [(m.group(1), m.group(2).strip("\"'")) for m in _PAIR.finditer(rest)]
    if pairs:
        return pairs
    parts = rest.split(None, 1)  # ENV NAME value with spaces
    return [(parts[0], parts[1].strip().strip("\"'"))] if len(parts) == 2 else []


def _secret_hit(ins: _Instruction, name: str, value: str) -> Hit | None:
    if not value or "$" in value:
        return None
    found = detect(value, name)
    if found is not None and found[0] != "generic":
        return None  # a provider pattern: the secret.* rule reports it on this line
    snippet = f"{ins.keyword} {name}=<redacted>"
    if found is not None:
        return _hit(
            "docker.env.secret",
            ins,
            f"{ins.keyword} sets {name} to a literal credential-like value (not shown); it is stored in the image layers.",
            snippet=snippet,
        )
    if (
        _CREDENTIAL_NAME.search(name)
        and not _NOT_A_SECRET_NAME.search(name)
        and len(value) >= 8
        and not (_WEAK_PLACEHOLDER.search(value) or _WEAK_NON_SECRET.match(value) or value.startswith(("/", "./", "~")))
        and "://" not in value
    ):
        return Hit(
            rule_id="docker.env.secret",
            line=ins.logical.at(ins.start)[0],
            column=1,
            end_line=ins.logical.at(ins.start)[0],
            message=f"{ins.keyword} sets {name} to a literal value (not shown); it is stored in the image layers.",
            snippet=snippet,
            severity="low",
            confidence="low",
        )
    return None


def check_dockerfile(text: str) -> list[Hit]:
    hits: list[Hit] = []
    stages: list[_Stage] = []
    aliases: dict[str, int] = {}
    earlier: list[str] = []
    for ins in _instructions(text):
        key, rest = ins.keyword, ins.rest.strip()
        if key == "FROM":
            tokens = [t for t in rest.split() if not t.startswith("--")]
            if not tokens:
                continue
            image = tokens[0]
            alias = tokens[2] if len(tokens) >= 3 and tokens[1].lower() == "as" else ""
            parent = aliases.get(image.lower())
            stages.append(_Stage(ins.logical.at(ins.start)[0], image, alias, parent))
            if alias:
                aliases[alias.lower()] = len(stages) - 1
            problem = _image_problem(image)
            if parent is None and problem is not None and image.lower() != "scratch":
                hits.append(
                    _hit(
                        "docker.from.latest",
                        ins,
                        f"Base image {image} is {'tagged latest' if problem == 'latest' else 'not tagged'}, so a build today "
                        "and a build next month can start from different images.",
                    )
                )
        elif key == "USER" and stages:
            stages[-1].user = rest.split()[0] if rest.split() else None
            stages[-1].user_line = ins.logical.at(ins.start)[0]
        elif key == "ADD":
            if not any(t.startswith("--checksum") for t in rest.split()) and _URL.search(rest):
                hits.append(
                    _hit(
                        "docker.add.remote_url",
                        ins,
                        "ADD downloads a remote URL with no checksum, so the image contains whatever the server returns.",
                    )
                )
        elif key == "RUN" and not rest.startswith("["):
            script = re.sub(r"^(?:--\S+\s+)+", "", rest)
            start = ins.start + (len(rest) - len(script)) + (len(ins.rest) - len(ins.rest.lstrip()))
            pipe = scan_logical(
                ins.logical, start, frozenset({PIPE}), earlier, {**SH_RULES, PIPE: "docker.run.pipe_to_shell"}
            )
            hits.extend(pipe)
            hits.extend(scan_logical(ins.logical, start, frozenset({CHMOD, EVAL}), earlier))
        elif key in ("ENV", "ARG"):
            for name, value in _split_assignments(rest):
                if (hit := _secret_hit(ins, name, value)) is not None:
                    hits.append(hit)
    if stages:
        hits.extend(_root_hit(stages))
    return hits


def _effective_user(stages: list[_Stage], index: int) -> str | None:
    seen = 0
    while seen <= len(stages):
        stage = stages[index]
        if stage.user is not None:
            return stage.user
        if stage.parent is None or stage.parent >= index:
            return None
        index = stage.parent
        seen += 1
    return None


def _root_hit(stages: list[_Stage]) -> list[Hit]:
    final = stages[-1]
    base = final
    guard = 0
    while base.parent is not None and base.parent < len(stages) and guard <= len(stages):
        base = stages[base.parent]
        guard += 1
    image = base.image.lower()
    if image == "scratch" or _NON_ROOT_IMAGE.search(image):
        return []
    user = _effective_user(stages, len(stages) - 1)
    if user is not None and user.lower() not in _ROOT_USERS:
        return []
    line = final.user_line if user is not None and final.user is not None else final.line
    message = (
        "The last USER instruction is root, so the container process runs as root."
        if user is not None
        else "The final stage has no USER instruction, so the container process runs as root."
    )
    return [
        Hit(
            rule_id="docker.user.root",
            line=line,
            column=1,
            end_line=line,
            message=message,
            snippet=f"FROM {final.image}" if user is None else f"USER {user}",
        )
    ]
