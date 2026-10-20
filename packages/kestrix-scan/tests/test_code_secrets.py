# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import pytest
from code_samples import fake, noise, private_key_block

from kestrix_scan.registry import RULES
from kestrix_scan.secrets import check_secrets, entropy, redact

PROVIDER_LINES = [
    ("aws_access_key_id", lambda: f"key_id = '{fake('aws_access_key_id')}'\n"),
    ("aws_secret_access_key", lambda: f"aws_secret_access_key = {fake('aws_secret_access_key')}\n"),
    ("github_token", lambda: f"TOKEN = '{fake('github_token')}'\n"),
    ("github_token", lambda: f"auth: {fake('github_pat')}\n"),
    ("slack_token", lambda: f"slack = '{fake('slack_token')}'\n"),
    ("stripe_live_key", lambda: f"stripe.api_key = '{fake('stripe_live_key')}'\n"),
    ("google_api_key", lambda: f'"maps": "{fake("google_api_key")}"\n'),
    ("jwt", lambda: f"Authorization: Bearer {fake('jwt')}\n"),
    ("anthropic_api_key", lambda: f"ANTHROPIC = '{fake('anthropic_api_key')}'\n"),
    ("openai_api_key", lambda: f"client = OpenAI(api_key='{fake('openai_api_key')}')\n"),
    ("private_key", private_key_block),
    ("generic", lambda: f'db_password = "{fake("generic")}"\n'),
    ("generic", lambda: f"export SERVICE_API_KEY={fake('generic')}\n"),
    ("generic", lambda: f'{{"client_secret": "{fake("generic")}"}}\n'),
    ("generic", lambda: f'password: str = "{fake("generic")}"\n'),
    ("generic", lambda: f"const password = `{fake('generic')}`;\n"),
]


@pytest.mark.parametrize(("kind", "make"), PROVIDER_LINES)
def test_secret_detected(kind: str, make) -> None:
    text = make()
    found = check_secrets(text)
    assert [hit.rule_id for hit in found] == [f"secret.{kind}"]
    assert found[0].line == 1


def test_a_template_literal_with_a_substitution_is_not_a_generic_secret() -> None:
    assert check_secrets("const password = `${process.env.PW}abcdefghijklmnop`;\n") == []


def test_every_secret_rule_is_covered() -> None:
    secret_rules = {rule.id for rule in RULES.values() if rule.language == "any"}
    assert {f"secret.{kind}" for kind, _ in PROVIDER_LINES} == secret_rules


NEGATIVE = [
    'password = "changeme-changeme-123"',
    'api_key = "your-api-key-goes-here-1234"',
    "token = '${GITHUB_TOKEN_FROM_THE_ENVIRONMENT}'",
    'secret = "<insert the secret value here>"',
    'password = "aaaaaaaaaaaaaaaaaaaaaaaa"',
    'token = "short"',
    'api_key_env = "' + noise(24) + '"',
    'token_url = "https://auth.example/oauth/token/v2"',
    'secret_path = "/etc/kestrix/secrets.json.backup"',
    'password_hash = "' + noise(40, alphabet="0123456789abcdef") + '"',
    'token = "kestrix.core.config.anthropic_key"',
    'API_KEY_NAME = "ANTHROPIC_API_KEY_VARIABLE"',
    "key_id = 'AKIAIOSFODNN7EXAMPLE'",
    "token = 'gh" + "p_" + "x" * 36 + "'",
    "private_key = load('-----BEGIN PRIVATE KEY-----')",
    "the word password: appears in prose",
    "color = '" + noise(24) + "'",
]


@pytest.mark.parametrize("text", NEGATIVE)
def test_not_a_secret(text: str) -> None:
    assert check_secrets(text + "\n") == []


def test_redacted_snippet_and_message_never_hold_the_value() -> None:
    token = fake("github_token")
    (hit,) = check_secrets(f"x = '{token}'\n")
    assert hit.snippet == "github_token:ghp_…"
    assert token not in hit.message and token[4:] not in hit.snippet
    assert (hit.line, hit.column) == (1, 6)


def test_private_key_spans_lines() -> None:
    (hit,) = check_secrets("header\n" + private_key_block())
    assert (hit.line, hit.end_line) == (2, 3)


def test_private_key_with_escaped_newlines() -> None:
    block = private_key_block().replace("\n", "\\n")
    assert [hit.rule_id for hit in check_secrets(f'"key": "{block}"\n')] == ["secret.private_key"]


def test_provider_match_wins_over_generic() -> None:
    assert [hit.rule_id for hit in check_secrets(f"api_token = '{fake('github_token')}'\n")] == ["secret.github_token"]


def test_redact_replaces_every_value() -> None:
    token, generic = fake("stripe_live_key"), fake("generic")
    text = f"call(key='{token}', password='{generic}')"
    cleaned = redact(text)
    assert token not in cleaned and generic not in cleaned
    assert "stripe_live_key:sk_l…" in cleaned and "generic:" in cleaned


def test_entropy() -> None:
    assert entropy("") == 0.0
    assert entropy("aaaa") == 0.0
    assert entropy("abcd") == 2.0
