# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""How each tool's findings map to benchmark categories.

Two scoring modes use these tables (see ``docs/benchmarks/benchmarkpython.md``):

- **category** (primary): a finding counts for a category through the explicit per-tool tables below. Kestrix and
  Bandit map by rule id, Semgrep by the CWEs in its rule metadata, the security-guidance regex layer by rule name.
  Rules not listed map to no category and are ignored.
- **strict CWE**: BenchmarkUtils' own rule. A finding counts only if a CWE the tool itself reports equals the test
  case's CWE. Tools that report no CWE (the security-guidance regex layer) have no strict score.

The tables are facts about each tool's rules (their names and the CWEs the tools assign); no tool's rule text is
copied here.
"""

from __future__ import annotations

from collections.abc import Iterable

# Benchmark categories: BenchmarkPython v0.1's own ids, plus the ids the owned cases add.
CATEGORIES: dict[str, str] = {
    "cmdi": "Command injection",
    "codeinj": "Code injection",
    "deserialization": "Insecure deserialization",
    "hash": "Weak hash",
    "ldapi": "LDAP injection",
    "pathtraver": "Path traversal",
    "redirect": "Open redirect",
    "securecookie": "Insecure cookie",
    "sqli": "SQL injection",
    "trustbound": "Trust boundary violation",
    "weakrand": "Weak randomness",
    "xpathi": "XPath injection",
    "xss": "Cross-site scripting",
    "xxe": "XML external entities",
    # Owned cases only.
    "ssrf": "Server-side request forgery",
    "tls": "TLS verification disabled",
    "jwt": "JWT signature not verified",
    "tempfile": "Insecure temporary file",
    "debug": "Debug mode enabled",
    "secrets": "Hard-coded credential",
    "agentconfig": "Risky Claude Code / MCP configuration",
}

# CWE -> category, shared by every tool that reports CWEs. Near-synonyms are grouped: CWE-95 (eval injection) is a
# child of CWE-94, CWE-338 of CWE-330, CWE-776 (entity expansion) sits with CWE-611 under the XML parser family.
# Neither suite has a separate "weak encryption" category, so CWE-327 counts as a weak hash.
CWE_CATEGORY: dict[int, str] = {
    22: "pathtraver",
    23: "pathtraver",
    36: "pathtraver",
    73: "pathtraver",
    77: "cmdi",
    78: "cmdi",
    79: "xss",
    80: "xss",
    1336: "xss",
    89: "sqli",
    90: "ldapi",
    94: "codeinj",
    95: "codeinj",
    215: "debug",
    489: "debug",
    259: "secrets",
    321: "secrets",
    798: "secrets",
    295: "tls",
    327: "hash",
    328: "hash",
    330: "weakrand",
    338: "weakrand",
    347: "jwt",
    377: "tempfile",
    501: "trustbound",
    502: "deserialization",
    601: "redirect",
    611: "xxe",
    776: "xxe",
    614: "securecookie",
    1004: "securecookie",
    643: "xpathi",
    918: "ssrf",
}

# Kestrix rule id -> category. `py.llm.output_to_sink` reports the sink's CWE per finding (94, 78, 89 or 22), so it
# maps through CWE_CATEGORY instead. `py.assert.security` and `dep.*` have no benchmark category.
KESTRIX_RULES: dict[str, str] = {
    "py.exec.eval": "codeinj",
    "py.exec.exec": "codeinj",
    "py.exec.compile": "codeinj",
    "py.subprocess.shell_true": "cmdi",
    "py.os.system": "cmdi",
    "py.deserialize.pickle": "deserialization",
    "py.deserialize.yaml_unsafe": "deserialization",
    "py.ml.unsafe_model_load": "deserialization",
    "py.sql.string_built": "sqli",
    "py.tls.verify_disabled": "tls",
    "py.crypto.weak_hash": "hash",
    "py.crypto.insecure_random": "weakrand",
    "py.tempfile.mktemp": "tempfile",
    "py.flask.debug": "debug",
    "py.jwt.no_verify": "jwt",
    "py.xml.unsafe_parser": "xxe",
    "py.path.traversal": "pathtraver",
    "py.archive.extract": "pathtraver",
    "py.ssrf.request": "ssrf",
    "py.redirect.open": "redirect",
    "py.xss.markup": "xss",
    "py.xss.reflected": "xss",
    "py.ldap.injection": "ldapi",
    "py.xpath.injection": "xpathi",
    "py.cookie.insecure": "securecookie",
    "py.trust_boundary.session": "trustbound",
}
KESTRIX_BY_CWE = frozenset({"py.llm.output_to_sink"})
KESTRIX_PREFIXES: dict[str, str] = {"config.": "agentconfig", "secret.": "secrets"}

# Bandit maps through the CWE Bandit itself reports, except these test ids, whose Bandit CWE is generic (CWE-20 on
# the XML and YAML checks) or names a different weakness than the check finds (CWE-78 on exec and eval, CWE-94 on
# Flask debug, CWE-327 on TLS protocol versions and ciphers). An empty string means "no category". Import-only checks
# such as B403 (pickle) and B404 (subprocess) keep Bandit's CWE, as BenchmarkUtils would score them.
BANDIT_OVERRIDES: dict[str, str] = {
    "B102": "codeinj",  # exec_used (Bandit: CWE-78)
    "B201": "debug",  # flask_debug_true (Bandit: CWE-94)
    "B304": "",  # ciphers (CWE-327): weak encryption, not a weak hash
    "B305": "",  # cipher_modes (CWE-327)
    "B307": "codeinj",  # eval (Bandit: CWE-78)
    "B310": "ssrf",  # urllib_urlopen: audit of URL schemes (Bandit: CWE-22)
    "B313": "xxe",  # xml_bad_cElementTree (CWE-20)
    "B314": "xxe",  # xml_bad_ElementTree
    "B315": "xxe",  # xml_bad_expatreader
    "B316": "xxe",  # xml_bad_expatbuilder
    "B317": "xxe",  # xml_bad_sax
    "B318": "xxe",  # xml_bad_minidom
    "B319": "xxe",  # xml_bad_pulldom
    "B320": "xxe",  # xml_bad_etree (lxml)
    "B405": "xxe",  # import_xml_etree
    "B406": "xxe",  # import_xml_sax
    "B407": "xxe",  # import_xml_expat
    "B408": "xxe",  # import_xml_minidom
    "B409": "xxe",  # import_xml_pulldom
    "B410": "xxe",  # import_lxml
    "B411": "xxe",  # import_xmlrpclib
    "B502": "tls",  # ssl_with_bad_version (CWE-327)
    "B503": "tls",  # ssl_with_bad_defaults (CWE-327)
    "B504": "tls",  # ssl_with_no_version (CWE-327)
    "B506": "deserialization",  # yaml_load (Bandit: CWE-20)
    "B615": "",  # huggingface_unsafe_download (CWE-494): no category
    "B701": "xss",  # jinja2_autoescape_false (Bandit: CWE-94)
    "B702": "xss",  # use_of_mako_templates (Bandit: CWE-80)
}

# security-guidance regex layer rule name -> category. JavaScript-only, workflow and cipher rules have no category.
SECURITY_GUIDANCE_RULES: dict[str, str] = {
    "eval_injection": "codeinj",
    "os_system_injection": "cmdi",
    "python_subprocess_shell": "cmdi",
    "pickle_deserialization": "deserialization",
    "pickle_variants_load": "deserialization",
    "pickle_wrapper_load": "deserialization",
    "marshal_loads": "deserialization",
    "shelve_open": "deserialization",
    "torch_unsafe_load": "deserialization",
    "unsafe_yaml_load": "deserialization",
    "yaml_unsafe_load_variants": "deserialization",
    "tls_verification_disabled": "tls",
    "xml_unsafe_parse": "xxe",
}


def categories_for_cwes(cwes: Iterable[int]) -> frozenset[str]:
    return frozenset(CWE_CATEGORY[c] for c in cwes if c in CWE_CATEGORY)


def kestrix_categories(rule_id: str, cwes: Iterable[int]) -> frozenset[str]:
    if rule_id in KESTRIX_BY_CWE:
        return categories_for_cwes(cwes)
    if rule_id in KESTRIX_RULES:
        return frozenset({KESTRIX_RULES[rule_id]})
    for prefix, category in KESTRIX_PREFIXES.items():
        if rule_id.startswith(prefix):
            return frozenset({category})
    return frozenset()


def bandit_categories(test_id: str, cwes: Iterable[int]) -> frozenset[str]:
    if test_id in BANDIT_OVERRIDES:
        category = BANDIT_OVERRIDES[test_id]
        return frozenset({category}) if category else frozenset()
    return categories_for_cwes(cwes)


def security_guidance_categories(rule_name: str) -> frozenset[str]:
    category = SECURITY_GUIDANCE_RULES.get(rule_name)
    return frozenset({category}) if category else frozenset()


def markdown_tables() -> str:
    """The mapping tables as Markdown, for the scorecard (``python -m kestrixscanbench.run mapping``)."""
    lines = ["| CWE | Category |", "| --- | --- |"]
    lines += [f"| CWE-{cwe} | `{cat}` |" for cwe, cat in sorted(CWE_CATEGORY.items())]
    lines += ["", "| Kestrix rule | Category |", "| --- | --- |"]
    lines += [f"| `{rule}` | `{cat}` |" for rule, cat in KESTRIX_RULES.items()]
    lines += [f"| `{rule}` | by the finding's CWE |" for rule in sorted(KESTRIX_BY_CWE)]
    lines += [f"| `{prefix}*` | `{cat}` |" for prefix, cat in KESTRIX_PREFIXES.items()]
    lines += ["", "| Bandit test id | Category |", "| --- | --- |"]
    lines += [f"| {test} | {f'`{cat}`' if cat else 'none'} |" for test, cat in BANDIT_OVERRIDES.items()]
    lines += ["| any other | by the CWE Bandit reports |"]
    lines += ["", "| security-guidance rule | Category |", "| --- | --- |"]
    lines += [f"| `{rule}` | `{cat}` |" for rule, cat in SECURITY_GUIDANCE_RULES.items()]
    lines += ["| any other | none |"]
    return "\n".join(lines) + "\n"
