# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""scripts/deploy_preflight.py: the go-live checks, their failures, and that no secret is ever printed."""

import argparse
import base64
import importlib.util
import json
import os
import secrets
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "deploy_preflight.py"
spec = importlib.util.spec_from_file_location("deploy_preflight", SCRIPT)
assert spec is not None and spec.loader is not None
preflight = importlib.util.module_from_spec(spec)
sys.modules["deploy_preflight"] = preflight
spec.loader.exec_module(preflight)


@pytest.fixture
def bundle(tmp_path):
    root = tmp_path / "static"
    (root / "assets").mkdir(parents=True)
    (root / "assets" / "index-AbCd1234.js").write_text("console.log(1)")
    (root / "assets" / "index-EfGh5678.css").write_text("a{}")
    (root / "index.html").write_text(
        '<!doctype html><script type="module" src="/assets/index-AbCd1234.js"></script>'
        '<link rel="stylesheet" href="/assets/index-EfGh5678.css">'
    )
    return root


@pytest.fixture
def strong_env(tmp_path):
    return {
        "KESTRIX_MODE": "hosted",
        "KESTRIX_PUBLIC_ORIGIN": "https://kestrix.preflight-test.org",
        "KESTRIX_SESSION_PEPPER": secrets.token_urlsafe(48),
        "KESTRIX_JWT_SECRET": secrets.token_urlsafe(48),
        "KESTRIX_HISTORY_KEY": base64.b64encode(os.urandom(32)).decode(),
        "KESTRIX_DB": str(tmp_path / "data" / "kestrix.db"),
        "KESTRIX_GOOGLE_CLIENT_ID": "1234-abc.apps.googleusercontent.com",
        "KESTRIX_GOOGLE_CLIENT_SECRET": secrets.token_urlsafe(24),
        "KESTRIX_GITHUB_CLIENT_ID": "Iv1.0123456789abcdef",
        "KESTRIX_GITHUB_CLIENT_SECRET": secrets.token_urlsafe(30),
        "KESTRIX_ABUSE_CONTACT": "abuse@preflight-test.org",
        "KESTRIX_CLIENT_IP_HEADER": "Fly-Client-IP",
    }


def args(bundle, **overrides):
    values = {"dry_run": False, "env_file": None, "static_dir": str(bundle), "url": None, "json": False}
    return argparse.Namespace(**{**values, **overrides})


def statuses(report):
    return {item.id: item.status for item in report.items}


def test_a_complete_environment_passes_every_check(strong_env, bundle):
    report = preflight.run(args(bundle), strong_env)
    failed = {i: s for i, s in statuses(report).items() if s == "FAIL"}
    assert not failed, [(i.id, i.message) for i in report.items if i.status == "FAIL"]
    assert statuses(report)["private-targets"] == "PASS" and statuses(report)["rate-limits:enforced"] == "PASS"
    assert statuses(report)["headers:page"] == "PASS" and statuses(report)["health"] == "PASS"


def test_the_dry_run_passes_without_any_configuration(bundle, monkeypatch):
    monkeypatch.delenv("KESTRIX_JWT_SECRET", raising=False)
    report = preflight.run(args(bundle, dry_run=True), {})
    assert not report.failed, [(i.id, i.message) for i in report.items if i.status == "FAIL"]


def test_an_empty_environment_fails_each_requirement(bundle):
    report = preflight.run(args(bundle), {})
    got = statuses(report)
    for item in (
        "KESTRIX_JWT_SECRET",
        "KESTRIX_SESSION_PEPPER",
        "KESTRIX_HISTORY_KEY",
        "KESTRIX_PUBLIC_ORIGIN",
        "oauth-any",
        "KESTRIX_ABUSE_CONTACT",
        "client-ip",
        "KESTRIX_DB",
        "settings",
    ):
        assert got[item] == "FAIL", item
    assert got["health"] == got["private-targets"] == "SKIP"


@pytest.mark.parametrize(
    ("secret", "why"),
    [
        ("short", "bytes"),
        ("a" * 64, "distinct"),
        ("abcabcabcabcabcabcabcabcabcabcabcabcabcabc", "distinct"),
        ("changeme-" + "Zq9xLm3vB7" * 4, "placeholder"),
        ("my-test-secret-" + secrets.token_urlsafe(30), "placeholder"),
    ],
)
def test_weak_secrets_fail_without_printing_them(strong_env, bundle, secret, why):
    strong_env["KESTRIX_JWT_SECRET"] = secret
    report = preflight.run(args(bundle), strong_env)
    item = next(i for i in report.items if i.id == "KESTRIX_JWT_SECRET")
    assert item.status == "FAIL" and why in item.message and secret not in item.message


def test_the_history_key_must_be_32_random_bytes(strong_env, bundle):
    for bad in ("not base64!!", base64.b64encode(b"short").decode(), base64.b64encode(b"\x01" * 32).decode()):
        strong_env["KESTRIX_HISTORY_KEY"] = bad
        assert statuses(preflight.run(args(bundle), strong_env))["KESTRIX_HISTORY_KEY"] == "FAIL"


def test_reused_secrets_fail(strong_env, bundle):
    strong_env["KESTRIX_SESSION_PEPPER"] = strong_env["KESTRIX_JWT_SECRET"]
    assert statuses(preflight.run(args(bundle), strong_env))["secrets-distinct"] == "FAIL"


@pytest.mark.parametrize(
    "origin",
    [
        "http://kestrix.preflight-test.org",
        "https://localhost",
        "https://127.0.0.1",
        "https://kestrix.example",
        "https://k.org/app",
    ],
)
def test_the_public_origin_must_be_a_real_https_host(strong_env, bundle, origin):
    strong_env["KESTRIX_PUBLIC_ORIGIN"] = origin
    assert statuses(preflight.run(args(bundle), strong_env))["KESTRIX_PUBLIC_ORIGIN"] == "FAIL"


def test_oauth_needs_complete_pairs_and_one_provider_is_a_warning(strong_env, bundle):
    del strong_env["KESTRIX_GITHUB_CLIENT_SECRET"]
    got = statuses(preflight.run(args(bundle), strong_env))
    assert got["oauth-github"] == "FAIL" and got["oauth-google"] == "PASS"
    del strong_env["KESTRIX_GITHUB_CLIENT_ID"]
    got = statuses(preflight.run(args(bundle), strong_env))
    assert got["oauth-github"] == "WARN" and "oauth-any" not in got


def test_missing_abuse_contact_and_client_ip_source_fail(strong_env, bundle):
    del strong_env["KESTRIX_ABUSE_CONTACT"], strong_env["KESTRIX_CLIENT_IP_HEADER"]
    got = statuses(preflight.run(args(bundle), strong_env))
    assert got["KESTRIX_ABUSE_CONTACT"] == got["client-ip"] == "FAIL"
    strong_env["KESTRIX_TRUST_PROXY_HEADERS"] = "1"
    assert statuses(preflight.run(args(bundle), strong_env))["client-ip"] == "PASS"


def test_hsts_preload_is_flagged_for_the_owner(strong_env, bundle):
    strong_env["KESTRIX_HSTS_PRELOAD"] = "1"
    assert statuses(preflight.run(args(bundle), strong_env))["hsts-preload"] == "WARN"


def test_database_files_must_be_private(strong_env, bundle, tmp_path):
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    db = data / "kestrix.db"
    db.write_bytes(b"")
    db.chmod(0o644)
    got = statuses(preflight.run(args(bundle), strong_env))
    assert got["db-mode:kestrix.db"] == "FAIL" and got["db-dir"] == "PASS"
    db.chmod(0o600)
    assert statuses(preflight.run(args(bundle), strong_env))["db-mode:kestrix.db"] == "PASS"


def test_the_real_database_is_never_touched(strong_env, bundle, tmp_path):
    preflight.run(args(bundle), strong_env)
    assert not (tmp_path / "data").exists()


def test_the_bundle_must_be_hashed_complete_and_free_of_inline_code(strong_env, bundle):
    index = bundle / "index.html"
    good = index.read_text()
    index.write_text(good.replace("index-AbCd1234.js", "main.js"))
    (bundle / "assets" / "main.js").write_text("x")
    assert statuses(preflight.run(args(bundle), strong_env))["bundle"] == "FAIL"
    index.write_text(good + "<script>alert(1)</script>")
    assert statuses(preflight.run(args(bundle), strong_env))["bundle"] == "FAIL"
    index.write_text(good.replace("index-EfGh5678.css", "gone-ZZZZ9999.css"))
    assert statuses(preflight.run(args(bundle), strong_env))["bundle"] == "FAIL"
    index.unlink()
    assert statuses(preflight.run(args(bundle), strong_env))["bundle"] == "FAIL"


def test_no_secret_value_is_ever_printed(strong_env, bundle, capsys):
    strong_env["KESTRIX_JWT_SECRET"] = "weakweakweakweakweakweakweakweakweak-" + secrets.token_urlsafe(8)
    report = preflight.run(args(bundle), strong_env)
    for text in (preflight.render(report, as_json=False), preflight.render(report, as_json=True)):
        for name in preflight.SECRET_VARS:
            value = strong_env.get(name)
            assert not value or value not in text, name
    assert preflight.Report(["super-secret-value"]).redact("boom super-secret-value boom") == "boom [redacted] boom"


def test_env_files_must_be_private_and_override_the_environment(strong_env, bundle, tmp_path):
    path = tmp_path / "staging.env"
    path.write_text("# staging\n" + "\n".join(f"export {k}='{v}'" for k, v in strong_env.items()) + "\nOTHER=1\n")
    path.chmod(0o644)
    report = preflight.run(args(bundle, env_file=str(path)), {})
    assert statuses(report)["env-file"] == "FAIL" and statuses(report)["KESTRIX_JWT_SECRET"] == "PASS"
    path.chmod(0o600)
    report = preflight.run(args(bundle, env_file=str(path)), {})
    assert not report.failed
    assert statuses(preflight.run(args(bundle, env_file=str(tmp_path / "none.env")), {})) == {"env-file": "FAIL"}


def test_header_problems_names_each_weakness():
    good = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
    }
    assert preflight.header_problems(good) == []
    weak = {
        **good,
        "Content-Security-Policy": "default-src *; script-src 'self' 'unsafe-inline'",
        "Server": "uvicorn/0.40",
    }
    del weak["Strict-Transport-Security"], weak["Permissions-Policy"]
    problems = " | ".join(preflight.header_problems(weak))
    for expected in ("unsafe", "object-src", "frame-ancestors", "HSTS", "Permissions-Policy", "Server"):
        assert expected in problems
    assert preflight.header_problems({})[0] == "Content-Security-Policy missing"


def test_the_live_probe_checks_health_and_headers():
    headers = {"Content-Security-Policy": "default-src 'self'"}
    report = preflight.Report([])
    preflight.check_live("https://kestrix.preflight-test.org/", report, fetch=lambda url: (200, headers))
    got = statuses(report)
    assert got["live:health"] == got["live:page"] == "PASS" and got["live:headers:api"] == "FAIL"

    def broken(url):
        raise OSError("down")

    report = preflight.Report([])
    preflight.check_live("https://kestrix.preflight-test.org", report, fetch=broken)
    assert statuses(report) == {"live": "FAIL"}


def test_exit_codes_and_json_output(bundle, capsys):
    assert preflight.main(["--dry-run", "--static-dir", str(bundle), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["FAIL"] == 0 and data["counts"]["PASS"] > 15
    assert preflight.main(["--static-dir", str(bundle / "missing")]) == 1
    assert "NOT READY" in capsys.readouterr().out
    with pytest.raises(SystemExit) as usage:
        preflight.main(["--dry-run", "--env-file", "x.env"])
    assert usage.value.code == 2
