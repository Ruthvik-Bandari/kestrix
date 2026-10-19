# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hard-coded secret detection for any text file.

Provider patterns match the documented shape of each credential. The generic rule matches a
credential-like name assigned a quoted literal (or an unquoted ``NAME=value`` line, as in ``.env``
files), and only when the value is at least 16 characters, has a Shannon entropy of at least 3.5
bits per character, mixes character classes and is not a placeholder.

The matched value never leaves this module: a ``Hit`` carries the kind and a redacted prefix
(``kind:abcd…``), and ``redact`` removes secret values from any other text before it is reported.
"""

from __future__ import annotations

import bisect
import math
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass

from .rules import Hit

MIN_GENERIC_LENGTH = 16
MIN_GENERIC_ENTROPY = 3.5
MIN_PROVIDER_ENTROPY = 3.0
PREFIX_CHARS = 4


@dataclass(frozen=True)
class _Pattern:
    kind: str
    regex: re.Pattern[str]
    group: int  # the capture group holding the secret value
    min_entropy: float


_PROVIDERS = (
    _Pattern("aws_access_key_id", re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])"), 1, 2.5),
    _Pattern(
        "aws_secret_access_key",
        re.compile(
            r"(?i)aws[a-z0-9_.-]{0,20}?(?:secret|sk)[a-z0-9_.-]{0,20}['\"]?\s*(?::|=|:=|=>)\s*['\"]?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"
        ),
        1,
        MIN_GENERIC_ENTROPY,
    ),
    _Pattern("github_token", re.compile(r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36,251})(?![A-Za-z0-9_])"), 1, 3.0),
    _Pattern("github_token", re.compile(r"(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{60,240})(?![A-Za-z0-9_])"), 1, 3.0),
    _Pattern("slack_token", re.compile(r"(?<![A-Za-z0-9])(xox[abpr]-[0-9]{6,20}-[A-Za-z0-9-]{10,200})"), 1, 3.0),
    _Pattern(
        "stripe_live_key", re.compile(r"(?<![A-Za-z0-9_])((?:sk|rk)_live_[A-Za-z0-9]{20,247})(?![A-Za-z0-9])"), 1, 3.0
    ),
    _Pattern("google_api_key", re.compile(r"(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])"), 1, 3.0),
    _Pattern(
        "private_key",
        re.compile(
            r"(-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----(?:\s|\\[nr])+"
            r"(?:[A-Za-z0-9-]{1,40}: ?[^\n\\]{0,200}(?:\r?\n|\\n)){0,4}(?:\s|\\[nr])*[A-Za-z0-9+/=]{40,})"
        ),
        1,
        0.0,
    ),
    _Pattern(
        "jwt",
        re.compile(r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
        1,
        3.0,
    ),
    _Pattern("anthropic_api_key", re.compile(r"(?<![A-Za-z0-9_-])(sk-ant-[A-Za-z0-9_-]{32,300})"), 1, 3.0),
    _Pattern(
        "openai_api_key",
        re.compile(
            r"(?<![A-Za-z0-9_-])(sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,300}"
            r"|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}))(?![A-Za-z0-9_-])"
        ),
        1,
        MIN_GENERIC_ENTROPY,
    ),
)

_NAME_WORDS = r"password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|token|private[_-]?key|client[_-]?secret"
_GENERIC_QUOTED = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{0,40}(?:" + _NAME_WORDS + r")[A-Za-z0-9_.-]{0,40})['\"]?"
    r"(?:\s*:\s*[A-Za-z_][\w\[\]., |]{0,40}?)?\s*(?:=|:|:=|=>)\s*[rbu]?(['\"])([^'\"\s\\]{16,200})\2"
)
_GENERIC_ENV = re.compile(
    r"(?m)^\s*(?:export\s+)?([A-Z0-9_]{0,40}(?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|ACCESS_KEY|AUTH_TOKEN|TOKEN|PRIVATE_KEY)[A-Z0-9_]{0,40})"
    r"=([^\s'\"#]{16,200})\s*$"
)
# Names that hold something about a secret (where it lives, its hash, its length), not the secret.
_NOT_A_SECRET_NAME = re.compile(
    r"(?i)(?:_|-|^)(?:url|uri|path|file|dir|name|env|var|header|field|type|id|hash|digest|sha\d*|checksum|"
    r"length|len|count|prefix|pattern|regex|re|format|endpoint|scope|param|key_?id)(?:_|-|$)"
)
_PLACEHOLDER = re.compile(
    r"(?i)changeme|change_me|example|xxxx|placeholder|dummy|sample|fake|test|your|redacted|todo|replace|"
    r"secret|password|token|insert|^\$|\$\{|\{\{|<|%\(|\*\*\*|0000000|1234567|abcdef"
)
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]+$")
_DOTTED_IDENTIFIER = re.compile(r"^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+$")


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in Counter(value).values())


def redacted(kind: str, value: str) -> str:
    return f"{kind}:{value[:PREFIX_CHARS]}…"


def _char_classes(value: str) -> int:
    return sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )


def _generic_value_ok(name: str, value: str) -> bool:
    return not (
        _NOT_A_SECRET_NAME.search(name)
        or _PLACEHOLDER.search(value)
        or _ENV_NAME.match(value)
        or _DOTTED_IDENTIFIER.match(value)
        or "://" in value
        or value.startswith(("/", "./", "~"))
        or len(set(value)) < 6
        or _char_classes(value) < 2
        or entropy(value) < MIN_GENERIC_ENTROPY
    )


def _matches(text: str) -> Iterator[tuple[str, int, int]]:
    """(kind, start, end) of every secret value in ``text``; provider matches win over generic ones."""
    spans: list[tuple[str, int, int]] = []
    for pattern in _PROVIDERS:
        for match in pattern.regex.finditer(text):
            value = match.group(pattern.group)
            if pattern.kind != "private_key" and (
                _PLACEHOLDER.search(value.split("_", 1)[-1]) or entropy(value) < pattern.min_entropy
            ):
                continue
            spans.append((pattern.kind, match.start(pattern.group), match.end(pattern.group)))
    for regex, name_group, value_group in ((_GENERIC_QUOTED, 1, 3), (_GENERIC_ENV, 1, 2)):
        for match in regex.finditer(text):
            start, end = match.start(value_group), match.end(value_group)
            if any(s < end and start < e for _, s, e in spans):
                continue
            if _generic_value_ok(match.group(name_group), match.group(value_group)):
                spans.append(("generic", start, end))
    yield from sorted(set(spans), key=lambda span: span[1])


def check_secrets(text: str) -> list[Hit]:
    """Secret hits in ``text``. A hit's snippet and message hold only the kind and a redacted prefix."""
    hits = []
    line_starts = [0, *(i + 1 for i, char in enumerate(text) if char == "\n")]
    for kind, start, end in _matches(text):
        line = bisect.bisect_right(line_starts, start)
        end_line = bisect.bisect_right(line_starts, max(start, end - 1))
        label = redacted(kind, text[start:end])
        hits.append(
            Hit(
                rule_id=f"secret.{kind}",
                line=line,
                column=start - line_starts[line - 1] + 1,
                end_line=end_line,
                message=f"Possible {kind.replace('_', ' ')} hard-coded in the file ({label}).",
                snippet=label,
            )
        )
    return hits


def redact(text: str) -> str:
    """``text`` with every secret value replaced by its redacted form."""
    pieces: list[str] = []
    last = 0
    for kind, start, end in _matches(text):
        if start < last:
            continue
        pieces.extend((text[last:start], redacted(kind, text[start:end])))
        last = end
    pieces.append(text[last:])
    return "".join(pieces)
