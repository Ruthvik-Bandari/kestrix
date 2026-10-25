# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""C and C++, Rust and Swift rules (Phase 5): the tokenizer, a positive and a negative case for every rule,
suppression, and pathological inputs."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from kestrix_scan import c_tokens
from kestrix_scan.analyze import scan_text
from kestrix_scan.php_tokens import ISTR, NAME, PUNCT, STR
from kestrix_scan.registry import RULES
from kestrix_scan.systems_rules import check_systems
from kestrix_scan.walk import Candidate


def ids(source: str, rel: str) -> list[tuple[str, int]]:
    result = check_systems(source, rel)
    assert isinstance(result, list), result
    return sorted((hit.rule_id, hit.line) for hit in result)


def rule_ids(source: str, rel: str) -> set[str]:
    return {rule for rule, _ in ids(source, rel)}


# ----- tokenizer


def kinds(source: str, language: str) -> list[tuple[str, str]]:
    tokens = c_tokens.tokenize(source, language)
    assert tokens is not None
    return [(t.kind, t.value) for t in tokens]


def test_c_strings_prefixes_raw_and_comments() -> None:
    toks = kinds('a = u8"x" L\'y\' R"d(a ) " b)d"; // c "q"\n/* x */ b', "c")
    assert (STR, "x") in toks and (STR, "y") in toks and (STR, 'a ) " b') in toks
    assert (NAME, "b") in toks and (STR, "q") not in toks


def test_c_preprocessor_and_unterminated_char_stay_on_their_line() -> None:
    toks = kinds("#error don't\nint x;", "c")
    assert toks[0] == (PUNCT, "#") and (NAME, "x") in toks


def test_rust_lifetimes_chars_raw_strings_and_nested_comments() -> None:
    toks = kinds(
        "fn f<'a>(x: &'a str) { let c = 'z'; let r = r#\"a \"q\" b\"#; /* /* in */ out */ let b = b'\\n'; }", "rust"
    )
    assert (STR, "z") in toks and (STR, 'a "q" b') in toks and (STR, "\\n") in toks
    assert (NAME, "out") not in toks and (NAME, "a") in toks


def test_rust_multiline_and_byte_strings() -> None:
    toks = kinds('let s = "one\ntwo"; let b = b"bytes"; let c = c"cstr";', "rust")
    assert (STR, "one\ntwo") in toks and (STR, "bytes") in toks and (STR, "cstr") in toks


def test_swift_interpolation_raw_and_multiline_strings() -> None:
    toks = c_tokens.tokenize(
        'let a = "x \\(user.name) \\(d["k"]) y"\nlet r = #"raw \\(no) \\#(yes)"#\nlet m = """\nm \\(z)\n"""', "swift"
    )
    assert toks is not None
    istr = [t for t in toks if t.kind == ISTR]
    assert [t.vars for t in istr] == [("user", "d"), ("yes",), ("z",)]


def test_swift_hash_directives_are_punctuation() -> None:
    assert kinds("#if DEBUG\n#endif", "swift")[:2] == [(PUNCT, "#"), (NAME, "if")]


@pytest.mark.parametrize("language", ("c", "rust", "swift"))
def test_tokenizer_never_raises_on_unterminated_input(language: str) -> None:
    for source in ('"abc', "'", "/* x", 'r#"x', '#"""x', 'R"x(abc', "\\(", 'u8"', "b'", '"\\(x'):
        assert c_tokens.tokenize(source, language) is not None


def test_tokenizer_bounds() -> None:
    assert c_tokens.tokenize("(" * (c_tokens.MAX_NESTING + 2), "c") is None
    assert c_tokens.tokenize("x " * (c_tokens.MAX_TOKENS + 2), "rust") is None
    assert c_tokens.tokenize("x" * (c_tokens.MAX_CHARS + 1), "swift") is None


# ----- C and C++

C_HEADER = "#include <stdio.h>\nstruct dev { char name[16]; };\n"


def c_fn(body: str) -> str:
    return C_HEADER + "int handle(char *input, struct dev *d) {\n    char buf[64];\n" + body + "\n    return 0;\n}\n"


def test_gets() -> None:
    assert ("c.buffer.gets", 5) in ids(c_fn("    gets(buf);"), "a.c")
    assert "c.buffer.gets" not in rule_ids(c_fn("    fgets(buf, sizeof buf, stdin);"), "a.c")
    assert "c.buffer.gets" not in rule_ids("char *gets(char *s);\n#define gets(x) safe(x)\nobj.gets(x);", "a.h")


@pytest.mark.parametrize(
    "body",
    [
        "    strcpy(buf, input);",
        "    strcat(buf, input);",
        "    strcpy(d->name, input);",
        '    sprintf(buf, "%s/%d", input, 3);',
        "    sprintf(buf, input);",
        "    vsprintf(buf, fmt, ap);",
        "    strcpy(&buf[0], input);",
    ],
)
def test_unbounded_copy_into_fixed_array(body: str) -> None:
    assert "c.buffer.unbounded_copy" in rule_ids(c_fn(body), "a.cpp")


@pytest.mark.parametrize(
    "body",
    [
        '    strcpy(buf, "fixed");',
        "    char *p = malloc(10);\n    strcpy(p, input);",
        '    sprintf(buf, "%.20s", input);',
        '    sprintf(buf, "%d-%d", a, b);',
        '    sprintf(buf, "%s", "literal");',
        '    snprintf(buf, sizeof buf, "%s", input);',
    ],
)
def test_unbounded_copy_negatives(body: str) -> None:
    assert "c.buffer.unbounded_copy" not in rule_ids(c_fn(body), "a.c")


def test_system_and_popen_with_built_command() -> None:
    assert ("c.exec.command", 5) in ids(c_fn("    system(input);"), "a.c")
    assert "c.exec.command" in rule_ids(c_fn('    FILE *f = popen(cmd, "r");'), "a.c")
    assert "c.exec.command" in rule_ids(c_fn('    execl("/bin/sh", "sh", "-c", input, NULL);'), "a.c")
    for safe in ('    system("ls -l");', "    system(CLEAR_CMD);", '    execl("/bin/ls", "ls", "-l", input, NULL);'):
        assert "c.exec.command" not in rule_ids(c_fn(safe), "a.c")


def test_format_string_not_literal() -> None:
    assert "c.format.nonliteral" in rule_ids(c_fn("    printf(input);"), "a.c")
    assert "c.format.nonliteral" in rule_ids(c_fn("    fprintf(stderr, d->name);"), "a.c")
    assert "c.format.nonliteral" in rule_ids(c_fn("    syslog(LOG_ERR, input);"), "a.c")


@pytest.mark.parametrize(
    "body",
    [
        '    printf("%s", input);',
        '    printf("a" PRIu64 "b");',
        '    printf(_("Usage"));',
        "    printf(fmt, a, b);",
        "    printf(USAGE);",
        "    printf(greeting);",
        "    obj.printf(input);",
    ],
)
def test_format_string_negatives(body: str) -> None:
    source = 'static const char *greeting = "hi";\n' + c_fn(body)
    assert "c.format.nonliteral" not in rule_ids(source, "a.c")


def test_format_in_macro_definition_is_not_reported() -> None:
    assert rule_ids("#define LOG(x) printf(x)\n#define E(x) \\\n  fprintf(stderr, x)\n", "a.h") == set()


def test_scanf_without_width() -> None:
    assert "c.input.scanf_string" in rule_ids(c_fn('    scanf("%s", buf);'), "a.c")
    assert "c.input.scanf_string" in rule_ids(c_fn('    sscanf(input, "%d %[^\\n]", &n, buf);'), "a.c")
    for safe in (
        '    scanf("%63s", buf);',
        '    scanf("%*s %d", &n);',
        '    scanf("%ms", &p);',
        '    scanf("%d", &n);',
    ):
        assert "c.input.scanf_string" not in rule_ids(c_fn(safe), "a.c")


def test_rand_next_to_security_word() -> None:
    assert "c.random.rand" in rule_ids(c_fn("    int session_key = rand();"), "a.c")
    assert "c.random.rand" in rule_ids("void make_token(char *t) { t[0] = rand() % 26; }", "a.c")
    assert "c.random.rand" not in rule_ids(c_fn("    int dice = rand() % 6;"), "a.c")
    assert "c.random.rand" not in rule_ids("void keyboard_jitter(void) { int d = rand(); }", "a.c")


def test_temp_name_functions() -> None:
    assert "c.tempfile.insecure" in rule_ids(c_fn("    char *t = tmpnam(NULL);"), "a.c")
    assert "c.tempfile.insecure" in rule_ids(c_fn("    mktemp(buf);"), "a.cc")
    assert "c.tempfile.insecure" not in rule_ids(c_fn("    int fd = mkstemp(buf);"), "a.c")


# ----- Rust


def test_command_through_a_shell_with_built_script() -> None:
    chain = 'use std::process::Command;\nfn run(user: &str) {\n    Command::new("sh").arg("-c").arg(format!("ls {}", user)).output();\n}\n'
    assert ("rust.exec.shell", 3) in ids(chain, "a.rs")
    bound = (
        'fn run(user: String) {\n    let mut c = Command::new("/bin/bash");\n    c.arg("-c");\n    c.arg(&user);\n}\n'
    )
    assert ("rust.exec.shell", 4) in ids(bound, "a.rs")
    inline = 'fn run(dir: &str) { Command::new("sh").args(["-c", &format!("ls {dir}")]).spawn(); }'
    assert "rust.exec.shell" in rule_ids(inline, "a.rs")


@pytest.mark.parametrize(
    "source",
    [
        'fn run() { Command::new("sh").arg("-c").arg("ls -la").output(); }',
        'fn run(user: &str) { Command::new("git").arg("log").arg(user).output(); }',
        'fn run(user: &str) { Command::new("sh").arg(user).output(); }',
        'fn run() { Command::new("sh").args(["-c", "echo hi"]).output(); }',
    ],
)
def test_command_negatives(source: str) -> None:
    assert "rust.exec.shell" not in rule_ids(source, "a.rs")


def test_tls_disabled() -> None:
    assert "rust.tls.disabled" in rule_ids(
        "let c = Client::builder().danger_accept_invalid_certs(true).build();", "a.rs"
    )
    assert "rust.tls.disabled" in rule_ids("b.danger_accept_invalid_hostnames(true);", "a.rs")
    assert "rust.tls.disabled" in rule_ids("ctx.set_verify(SslVerifyMode::NONE);", "a.rs")
    verifier = "impl ServerCertVerifier for V {\n    fn verify_server_cert(&self, e: &CertificateDer<'_>) -> Result<ServerCertVerified, Error> {\n        Ok(ServerCertVerified::assertion())\n    }\n}\n"
    assert ("rust.tls.disabled", 2) in ids(verifier, "a.rs")
    assert rule_ids("let c = Client::builder().danger_accept_invalid_certs(false).build();", "a.rs") == set()
    checked = verifier.replace(
        "Ok(ServerCertVerified::assertion())",
        "self.inner.verify_server_cert(e)?;\n        Ok(ServerCertVerified::assertion())",
    )
    assert rule_ids(checked, "a.rs") == set()


def test_unsafe_unchecked_operation_on_input() -> None:
    source = "fn parse(data: &[u8]) {\n    let len = data[0] as usize;\n    let mut v: Vec<u8> = Vec::new();\n    unsafe { v.set_len(len); }\n}\n"
    assert ("rust.unsafe.input", 4) in ids(source, "a.rs")
    reader = "fn load<R: Read>(r: &mut R) {\n    let mut hdr = [0u8; 4];\n    r.read_exact(&mut hdr);\n    let n = u32::from_le_bytes(hdr) as usize;\n    unsafe { ptr::copy_nonoverlapping(src, dst, n); }\n}\n"
    assert "rust.unsafe.input" in rule_ids(reader, "a.rs")
    env = "fn main() {\n    let i: usize = std::env::args().nth(1).unwrap().parse().unwrap();\n    unsafe { let x = *TABLE.get_unchecked(i); }\n}\n"
    assert "rust.unsafe.input" in rule_ids(env, "a.rs")


@pytest.mark.parametrize(
    "source",
    [
        "fn f(n: usize) { let mut v = Vec::new(); unsafe { v.set_len(n); } }",
        "fn f(data: &[u8]) { let n = 4; unsafe { v.set_len(n); } }",
        "fn f(data: &[u8]) { let len = data.len(); let x = len.add(1); }",
        "fn f(data: &[u8]) { unsafe { libc::free(p); } }",
    ],
)
def test_unsafe_negatives(source: str) -> None:
    assert "rust.unsafe.input" not in rule_ids(source, "a.rs")


# ----- Swift

TRUST_ALL = """class D: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}
"""


def test_trust_all_challenge_handler() -> None:
    assert ("swift.tls.trust_all", 4) in ids(TRUST_ALL, "a.swift")
    evaluated = TRUST_ALL.replace(
        "        completionHandler(",
        "        guard SecTrustEvaluateWithError(challenge.protectionSpace.serverTrust!, nil) else { return }\n        completionHandler(",
    )
    assert rule_ids(evaluated, "a.swift") == set()
    pinned = TRUST_ALL.replace(
        "        completionHandler(",
        "        guard pinner.matches(challenge) else { return }\n        completionHandler(",
    )
    assert rule_ids(pinned, "a.swift") == set()
    assert (
        rule_ids(
            TRUST_ALL.replace("URLCredential(trust:", "URLCredential(user: u, password: p, persistence: .none) //"),
            "a.swift",
        )
        == set()
    )


def test_disabled_evaluators() -> None:
    source = 'let m = ServerTrustManager(evaluators: ["dev.example.com": DisabledTrustEvaluator()])'
    assert "swift.tls.trust_all" in rule_ids(source, "a.swift")
    assert rule_ids("final class DisabledTrustEvaluator: ServerTrustEvaluating {}", "a.swift") == set()
    assert (
        rule_ids('let m = ServerTrustManager(evaluators: ["h": PinnedCertificatesTrustEvaluator()])', "a.swift")
        == set()
    )


def test_secret_in_user_defaults() -> None:
    assert "swift.storage.userdefaults_secret" in rule_ids(
        'UserDefaults.standard.set(token, forKey: "authToken")', "a.swift"
    )
    assert "swift.storage.userdefaults_secret" in rule_ids('defaults.setValue(pw, forKey: "user_password")', "a.swift")
    assert "swift.storage.userdefaults_secret" in rule_ids('@AppStorage("apiKey") var key = ""', "a.swift")
    for safe in (
        'UserDefaults.standard.set(token, forKey: "deviceToken")',
        'UserDefaults.standard.set(true, forKey: "onboarded")',
        'keychain.set(token, forKey: "authToken")',
        "UserDefaults.standard.set(token, forKey: key)",
    ):
        assert "swift.storage.userdefaults_secret" not in rule_ids(safe, "a.swift")


def test_app_transport_security_in_plist() -> None:
    plist = "<dict>\n<key>NSAppTransportSecurity</key>\n<dict>\n  <key>NSAllowsArbitraryLoads</key>\n  <true/>\n</dict>\n</dict>\n"
    result = check_systems(plist, "App/Info.plist")
    assert isinstance(result, list) and [(h.rule_id, h.line, h.severity) for h in result] == [
        ("swift.ats.arbitrary_loads", 4, None)
    ]
    exception = plist.replace("NSAllowsArbitraryLoads", "NSExceptionAllowsInsecureHTTPLoads")
    result = check_systems(exception, "Info.plist")
    assert isinstance(result, list) and result[0].severity == "low"
    assert check_systems(plist.replace("<true/>", "<false/>"), "Info.plist") == []


# ----- registry, suppression and the scan path


def test_every_phase5_rule_is_registered_with_sources() -> None:
    phase5 = [rule for rule in RULES.values() if rule.language in {"c", "rust", "swift"}]
    assert len(phase5) == 13
    assert all(rule.sources and rule.cwe.startswith("CWE-") and rule.fix for rule in phase5)


def test_suppression_with_reason(tmp_path: Path) -> None:
    source = c_fn("    // kestrix: ignore[c.buffer.gets] legacy test harness, stdin is a fixed file\n    gets(buf);")
    path = tmp_path / "a.c"
    path.write_text(source, encoding="utf-8")
    findings, _, suppressed, skip = scan_text(source, Candidate(path=path, rel="a.c"))
    assert skip is None and suppressed == 1 and not [f for f in findings if f.rule_id == "c.buffer.gets"]


def test_minified_and_too_complex_are_skipped() -> None:
    assert check_systems("x" * 2000, "a.c") == "minified"
    assert check_systems("(\n" * (c_tokens.MAX_NESTING + 2), "a.rs") == "too_complex"


@pytest.mark.parametrize(
    ("rel", "source"),
    [
        ("a.c", '"' * 200_000),
        ("a.c", "/*" * 100_000),
        ("a.cpp", 'R"x(' * 50_000),
        ("a.c", "printf(" * 400 + ")" * 400),
        ("a.c", "char buf[1];\n" + "strcpy(buf, x);\n" * 20_000),
        ("a.rs", "'a " * 100_000),
        ("a.rs", "/* " * 100_000),
        ("a.rs", "fn f(d: &[u8]) {\n" + "let a = d;\n" * 20_000 + "unsafe { v.set_len(a); }\n}\n"),
        ("a.rs", 'Command::new("sh").arg("-c")' + ".arg(x)" * 20_000 + ";"),
        ("a.swift", '"\\(' * 100_000),
        ("a.swift", "func f() {\n" * 300 + "}\n" * 300),
        ("Info.plist", "<key>NSAllowsArbitraryLoads</key><true/>\n" * 20_000),
    ],
)
def test_pathological_inputs_are_bounded_and_fast(rel: str, source: str) -> None:
    started = time.perf_counter()
    result = check_systems(source, rel)
    assert isinstance(result, (list, str))
    assert time.perf_counter() - started < 10
