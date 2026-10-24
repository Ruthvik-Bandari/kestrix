# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Phase 3 rules: GitHub Actions, Dockerfile, shell, Terraform and Kubernetes. A positive and a negative case per rule."""

import textwrap
import time
from pathlib import Path

import pytest

from kestrix_scan.analyze import scan_text
from kestrix_scan.iac import check_iac, iac_kind
from kestrix_scan.registry import RULES, Hit
from kestrix_scan.walk import Candidate

WF = ".github/workflows/ci.yml"
FAKE_KEY = "Zq9x2LmP7v" + "Te4RwN8cYb"  # built at run time so the scanner's self-scan does not see a literal secret


def hits(source: str, rel: str) -> list[Hit]:
    result = check_iac(textwrap.dedent(source), rel)
    assert isinstance(result, list), result
    return result


def ids(source: str, rel: str) -> set[str]:
    return {h.rule_id for h in hits(source, rel)}


def wf(body: str, *, on: str = "pull_request", extra: str = "") -> str:
    """A workflow with the given steps (already indented by six spaces)."""
    return f"on: {on}\n{extra}jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n{body}"


# (rule id, file name, source that fires it, source that does not)
CASES = [
    (
        "gha.pr_target.checkout_head",
        WF,
        wf(
            "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
            on="pull_request_target",
        ),
        wf(
            "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        ),
    ),
    (
        "gha.pr_target.checkout_head",
        WF,
        wf(
            "      - uses: actions/checkout@v4\n        with:\n          repository: ${{ github.event.workflow_run.head_repository.full_name }}\n"
            "          ref: ${{ github.event.workflow_run.head_sha }}\n",
            on="[push, workflow_run]",
        ),
        wf("      - uses: actions/checkout@v4\n", on="pull_request_target"),
    ),
    (
        "gha.pr_target.checkout_head",
        WF,
        wf("      - run: gh pr checkout ${{ github.event.number }}\n", on="pull_request_target"),
        wf("      - run: gh pr view ${{ github.event.number }}\n", on="pull_request_target"),
    ),
    (
        "gha.injection.untrusted_context",
        WF,
        wf('      - run: echo "${{ github.event.pull_request.title }}"\n'),
        wf('      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: echo "$TITLE"\n'),
    ),
    (
        "gha.injection.untrusted_context",
        WF,
        wf("      - run: |\n          echo start\n          git checkout ${{ github.head_ref }}\n"),
        wf("      - if: contains(github.event.pull_request.title, 'wip')\n        run: echo skip\n"),
    ),
    (
        "gha.injection.untrusted_context",
        WF,
        wf(
            "      - uses: actions/github-script@v7\n        with:\n          script: |\n"
            "            console.log('${{ github.event.issue.body }}')\n"
        ),
        wf("      - run: echo ${{ github.event.pull_request.number }} ${{ github.sha }}\n"),
    ),
    (
        "gha.action.unpinned",
        WF,
        wf("      - uses: softprops/action-gh-release@v2\n"),
        wf("      - uses: softprops/action-gh-release@c95fe1489396fe8a9eb87c0abf8aa5b2ef267fda # v2\n"),
    ),
    (
        "gha.action.unpinned",
        WF,
        "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/build.yml@main\n",
        "on: push\njobs:\n  build:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./local\n"
        "      - uses: docker://alpine:3.20\n      - uses: github/codeql-action/init@v3\n",
    ),
    (
        "gha.permissions.write_all",
        WF,
        "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo hi\n",
        "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo hi\n",
    ),
    (
        "gha.permissions.write_all",
        WF,
        "on: push\njobs:\n  a:\n    permissions: write-all\n    runs-on: x\n    steps:\n      - run: echo hi\n",
        "on: push\njobs:\n  a:\n    permissions: { contents: write }\n    runs-on: x\n    steps:\n      - run: echo hi\n",
    ),
    (
        "gha.permissions.missing",
        WF,
        wf("      - run: ./deploy.sh\n        env:\n          TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"),
        wf(
            "      - run: ./deploy.sh\n        env:\n          TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n",
            extra="permissions: {}\n",
        ),
    ),
    (
        "gha.permissions.missing",
        WF,
        "on: push\njobs:\n  call:\n    uses: ./.github/workflows/x.yml\n    secrets: inherit\n",
        wf("      - run: echo ${{ secrets.GITHUB_TOKEN }}\n"),
    ),
    (
        "gha.secrets.echoed",
        WF,
        wf('      - run: echo "token is ${{ secrets.API_TOKEN }}"\n', extra="permissions: read-all\n"),
        wf(
            '      - run: |\n          echo "::add-mask::${{ secrets.API_TOKEN }}"\n          echo "${{ secrets.API_TOKEN }}" | docker login --password-stdin\n'
            '          echo "k=${{ secrets.API_TOKEN }}" >> "$GITHUB_ENV"\n',
            extra="permissions: read-all\n",
        ),
    ),
    (
        "docker.user.root",
        "Dockerfile",
        'FROM python:3.12\nCOPY . /app\nCMD ["python", "/app/x.py"]\n',
        "FROM python:3.12\nUSER 10001\n",
    ),
    (
        "docker.user.root",
        "Dockerfile",
        "FROM python:3.12\nUSER root\n",
        "FROM python:3.12\nUSER root\nRUN x\nUSER app\n",
    ),
    (
        "docker.user.root",
        "a/Dockerfile.prod",
        "FROM node:22 AS build\nUSER app\nFROM node:22 AS final\nCOPY --from=build /a /a\n",
        "FROM node:22 AS base\nUSER app\nFROM base AS final\nCOPY . .\n",
    ),
    ("docker.user.root", "Containerfile", "FROM fedora:40\n", "FROM scratch\nCOPY app /app\n"),
    (
        "docker.add.remote_url",
        "Dockerfile",
        "FROM alpine:3.20\nADD https://example.com/tool.tar.gz /opt/\nUSER 1\n",
        "FROM alpine:3.20\nADD --checksum=sha256:"
        + "a" * 64
        + " https://example.com/tool.tar.gz /opt/\nADD app.tar.gz /opt/\nUSER 1\n",
    ),
    (
        "docker.run.pipe_to_shell",
        "Dockerfile",
        "FROM alpine:3.20\nRUN apk add curl \\\n && curl -fsSL https://example.com/install.sh | sh\nUSER 1\n",
        "FROM alpine:3.20\nRUN curl -fsSL -o /tmp/i.sh https://example.com/i.sh && sha256sum -c /tmp/i.sum && sh /tmp/i.sh\nUSER 1\n",
    ),
    ("docker.from.latest", "Dockerfile", "FROM ubuntu:latest\nUSER 1\n", "FROM ubuntu:24.04\nUSER 1\n"),
    (
        "docker.from.latest",
        "Dockerfile",
        "FROM --platform=linux/amd64 ubuntu\nUSER 1\n",
        "FROM ubuntu@sha256:" + "b" * 64 + "\nUSER 1\n",
    ),
    (
        "docker.env.secret",
        "Dockerfile",
        "FROM alpine:3.20\nENV DB_PASSWORD=hunter2hunter2\nUSER 1\n",
        "FROM alpine:3.20\nENV DB_PASSWORD_FILE=/run/secrets/db DB_HOST=db\nARG NPM_TOKEN\nENV TOKEN=${NPM_TOKEN}\nUSER 1\n",
    ),
    (
        "docker.env.secret",
        "Dockerfile",
        f'FROM alpine:3.20\nARG API_KEY="{FAKE_KEY}"\nUSER 1\n',
        "FROM alpine:3.20\nENV API_KEY=changeme\nUSER 1\n",
    ),
    (
        "sh.pipe_to_shell",
        "install.sh",
        "#!/bin/sh\ncurl -fsSL https://example.com/i.sh | sudo bash -s -- --yes\n",
        "#!/bin/sh\ncurl -fsSL https://example.com/i.sh -o i.sh\nsha256sum -c i.sum\nsh i.sh\ncurl -s x | sha256sum\n",
    ),
    (
        "sh.pipe_to_shell",
        "run.bash",
        "bash <(curl -s https://example.com/i.sh)\n",
        'echo "curl x | sh is a bad idea"  # curl x | sh\n',
    ),
    (
        "sh.eval.variable",
        "a.sh",
        'cmd="$1"\neval "$cmd"\n',
        'eval "$(ssh-agent -s)"\neval $(go env)\necho eval\n',
    ),
    ("sh.eval.variable", "a.sh", "if true; then eval $CMD --flag; fi\n", "eval 'echo hi'\n"),
    (
        "sh.rm_rf.unguarded_variable",
        "a.sh",
        'rm -rf "$BUILD_DIR/"\n',
        'rm -rf "${BUILD_DIR:?}/"\nrm -rf "$BUILD_DIR/cache"\nrm -rf /tmp/build\nrm -rf "$HOME/"\n',
    ),
    (
        "sh.rm_rf.unguarded_variable",
        "a.sh",
        "rm -fr $OUT/*\n",
        'OUT=$(mktemp -d)\nrm -rf $OUT\n[ -n "$DIR" ] || exit 1\nrm -rf $DIR\nrm -r $X\n',
    ),
    (
        "sh.chmod.world_writable",
        "a.sh",
        "chmod -R 777 /var/app\n",
        "chmod 755 /var/app\nchmod 1777 /tmp/x\nchmod +x run.sh\n",
    ),
    (
        "sh.chmod.world_writable",
        "a.sh",
        "sudo chmod a+w data\nchmod o=rw data2\n",
        "chmod u+w,g+w data\nchmod a-w data\nchmod 644 f\n",
    ),
    (
        "tf.s3.public_access",
        "main.tf",
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl    = "public-read"\n}\n',
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl    = "private"\n}\n',
    ),
    (
        "tf.s3.public_access",
        "main.tf",
        'resource "aws_s3_bucket_public_access_block" "b" {\n  bucket = aws_s3_bucket.b.id\n  block_public_acls = false\n  block_public_policy = true\n}\n',
        'resource "aws_s3_bucket_public_access_block" "b" {\n  bucket = aws_s3_bucket.b.id\n  block_public_acls = true\n  block_public_policy = var.block\n}\n',
    ),
    (
        "tf.sg.open_admin_port",
        "net.tf",
        'resource "aws_security_group" "s" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
        'resource "aws_security_group" "s" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["10.0.0.0/8"]\n  }\n  ingress {\n    from_port = 443\n    to_port = 443\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n  egress {\n    from_port = 0\n    to_port = 0\n    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
    ),
    (
        "tf.sg.open_admin_port",
        "net.tf",
        'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = 0\n  to_port = 10000\n  protocol = "tcp"\n  cidr_blocks = [\n    "0.0.0.0/0",\n  ]\n}\n',
        'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = var.port\n  to_port = var.port\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n',
    ),
    (
        "tf.sg.open_admin_port",
        "net.tf",
        'resource "aws_vpc_security_group_ingress_rule" "r" {\n  from_port = 5432\n  to_port = 5432\n  ip_protocol = "tcp"\n  cidr_ipv4 = "0.0.0.0/0"\n}\n',
        'resource "aws_vpc_security_group_ingress_rule" "r" {\n  from_port = 5432\n  to_port = 5432\n  ip_protocol = "udp"\n  cidr_ipv4 = "0.0.0.0/0"\n}\n',
    ),
    (
        "tf.storage.unencrypted",
        "db.tf",
        'resource "aws_db_instance" "d" {\n  storage_encrypted = false\n}\n',
        'resource "aws_db_instance" "d" {\n  storage_encrypted = true\n}\nresource "aws_ebs_volume" "v" {\n  size = 1\n}\n',
    ),
    (
        "tf.storage.unencrypted",
        "db.tf",
        'resource "aws_instance" "i" {\n  root_block_device {\n    encrypted = false\n  }\n}\n',
        '# encrypted = false\nresource "aws_instance" "i" {\n  root_block_device {\n    encrypted = var.enc\n  }\n}\n',
    ),
]

POD = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: a\n      image: x\n"
SAFE_CONTEXT = "      securityContext:\n        runAsNonRoot: true\n        allowPrivilegeEscalation: false\n"
K8S_CASES = [
    ("k8s.pod.privileged", POD + "      securityContext:\n        privileged: true\n", POD + SAFE_CONTEXT),
    (
        "k8s.pod.host_path",
        POD + "  volumes:\n    - name: d\n      hostPath:\n        path: /var/run/docker.sock\n",
        POD + SAFE_CONTEXT + "  volumes:\n    - name: d\n      emptyDir: {}\n",
    ),
    (
        "k8s.pod.privilege_escalation",
        POD + "      securityContext:\n        allowPrivilegeEscalation: true\n",
        POD + SAFE_CONTEXT,
    ),
    ("k8s.pod.run_as_root", POD + "      securityContext:\n        runAsUser: 0\n", POD + SAFE_CONTEXT),
    (
        "k8s.pod.run_as_root",
        POD + "  securityContext:\n    runAsNonRoot: false\n",
        POD + "  securityContext:\n    runAsNonRoot: true\n",
    ),
    ("k8s.pod.no_run_as_nonroot", POD, POD + "      securityContext: {runAsUser: 1000}\n"),
    ("k8s.pod.host_namespace", POD + "  hostNetwork: true\n", POD + SAFE_CONTEXT + "  hostNetwork: false\n"),
    (
        "k8s.pod.privileged",
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: a\n          securityContext:\n            privileged: true\n",
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      securityContext:\n        runAsNonRoot: true\n      containers:\n        - name: a\n          securityContext: {privileged: false}\n",
    ),
]


@pytest.mark.parametrize(("rule_id", "rel", "bad", "good"), CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_rule_fires_and_stays_quiet(rule_id: str, rel: str, bad: str, good: str) -> None:
    assert rule_id in ids(bad, rel)
    assert rule_id not in ids(good, rel)


@pytest.mark.parametrize(("rule_id", "bad", "good"), K8S_CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(K8S_CASES)])
def test_kubernetes_rules(rule_id: str, bad: str, good: str) -> None:
    assert rule_id in ids(bad, "deploy/app.yaml")
    assert rule_id not in ids(good, "deploy/app.yaml")


def test_every_phase3_rule_has_a_positive_and_a_negative_case() -> None:
    covered = {case[0] for case in CASES} | {case[0] for case in K8S_CASES}
    phase3 = {
        r.id
        for r in RULES.values()
        if r.language in {"github-actions", "dockerfile", "shell", "terraform", "kubernetes"}
    }
    assert phase3 and phase3 <= covered
    assert {r.id.split(".")[0] for r in RULES.values() if r.id in phase3} == {"gha", "docker", "sh", "tf", "k8s"}


def test_pr_target_hit_names_the_ref_line() -> None:
    source = wf(
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
        on="pull_request_target",
    )
    [hit] = [h for h in hits(source, WF) if h.rule_id == "gha.pr_target.checkout_head"]
    assert hit.line == 8 and "head.sha" in hit.snippet


def test_injection_line_numbers_follow_the_block_scalar() -> None:
    source = wf("      - run: |\n          echo a\n          echo ${{ github.event.comment.body }}\n")
    [hit] = [h for h in hits(source, WF) if h.rule_id == "gha.injection.untrusted_context"]
    assert hit.line == 8 and hit.cwe == "CWE-78"
    script = wf(
        "      - uses: actions/github-script@v7\n        with:\n          script: console.log(${{ github.head_ref }})\n"
    )
    [js] = [h for h in hits(script, WF) if h.rule_id == "gha.injection.untrusted_context"]
    assert js.cwe == "CWE-94"


def test_untrusted_contexts_include_the_documented_fields() -> None:
    for field in (
        "github.event.issue.title",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
        "github.event.review.body",
        "github.event.commits[0].message",
        "github.event.head_commit.author.email",
        "github.event.workflow_run.head_branch",
        "github.event.pages[0].page_name",
        "github.head_ref",
    ):
        assert "gha.injection.untrusted_context" in ids(wf(f"      - run: echo ${{{{ {field} }}}}\n"), WF), field


def test_trusted_contexts_are_not_injection() -> None:
    for field in (
        "github.sha",
        "github.actor",
        "github.event.pull_request.number",
        "github.event.repository.name",
        "runner.os",
    ):
        assert "gha.injection.untrusted_context" not in ids(wf(f"      - run: echo ${{{{ {field} }}}}\n"), WF), field


def test_pinned_comment_tag_and_first_party_are_not_reported_as_unpinned() -> None:
    source = wf("      - uses: actions/checkout@v4\n      - uses: github/codeql-action/analyze@v3\n")
    assert "gha.action.unpinned" not in ids(source, WF)
    [hit] = hits(wf("      - uses: astral-sh/setup-uv@v6\n"), WF)
    assert hit.rule_id == "gha.action.unpinned" and "astral-sh/setup-uv" in hit.message


def test_secret_name_is_never_a_finding_value() -> None:
    source = wf('      - run: echo "${{ secrets.API_TOKEN }}"\n', extra="permissions: read-all\n")
    [hit] = [h for h in hits(source, WF) if h.rule_id == "gha.secrets.echoed"]
    assert "secrets.API_TOKEN" in hit.snippet and hit.line == 7


def test_docker_secret_value_is_never_printed(tmp_path: Path) -> None:
    value = FAKE_KEY
    candidate = Candidate(path=tmp_path / "Dockerfile", rel="Dockerfile")
    findings, _, _, skip = scan_text(f"FROM alpine:3.20\nARG API_KEY={value}\nUSER 1\n", candidate)
    assert skip is None
    [finding] = [f for f in findings if f.rule_id == "docker.env.secret"]
    assert value not in repr(finding) and "<redacted>" in finding.snippet and finding.line == 2
    assert not [f for f in findings if f.rule_id.startswith("secret.")]  # one finding per credential


def test_docker_provider_secret_is_reported_once_by_the_secret_rule(tmp_path: Path) -> None:
    token = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
    candidate = Candidate(path=tmp_path / "Dockerfile", rel="Dockerfile")
    findings, _, _, _ = scan_text(f"FROM alpine:3.20\nENV GITHUB_TOKEN={token}\nUSER 1\n", candidate)
    assert [f.rule_id for f in findings] == ["secret.github_token"]
    assert token not in repr(findings)


def test_dockerfile_continuations_comments_and_heredocs() -> None:
    source = (
        "FROM alpine:3.20\n# comment\nRUN set -eux; \\\n    # a comment inside the instruction\n    chmod -R 777 /data\n"
        "RUN <<EOF\ncurl x | sh\nEOF\nUSER 1\n"
    )
    found = {(h.rule_id, h.line) for h in hits(source, "Dockerfile")}
    assert ("sh.chmod.world_writable", 5) in found
    assert not any(rule == "docker.run.pipe_to_shell" for rule, _ in found)  # heredoc body is not scanned


def test_shell_lines_are_reported_with_their_physical_line() -> None:
    script = (
        "#!/bin/sh\nset -e\ncat <<'EOF' > x\neval \"$A\"\nEOF\ncurl -fsSL \\\n  https://x.example/i.sh \\\n  | sh\n"
    )
    found = {(h.rule_id, h.line) for h in hits(script, "i.sh")}
    assert found == {("sh.pipe_to_shell", 6)}
    assert not any(rule == "sh.eval.variable" for rule, _ in found)


def test_terraform_comments_heredocs_and_one_line_blocks() -> None:
    source = (
        '# acl = "public-read"\nresource "aws_s3_bucket" "b" {\n  policy = <<EOT\n  {"acl": "public-read"}\nEOT\n'
        '  /* encrypted = false */\n  acl = "private"\n}\n'
        'resource "aws_security_group" "s" {\n  ingress { from_port = 3306 to_port = 3306 protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] }\n}\n'
    )
    assert ids(source, "main.tf") == {"tf.sg.open_admin_port"}


def test_kubernetes_helm_templates_and_non_manifests_are_left_alone() -> None:
    helm = "{{- if .Values.x }}\napiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: a\n    securityContext:\n      privileged: true\n{{- end }}\n"
    assert hits(helm, "chart/templates/pod.yaml") == []
    assert hits("name: x\nversion: 1\nitems:\n  - containers: []\n", "values.yaml") == []


def test_kubernetes_multi_document_and_list() -> None:
    source = POD + "---\n" + POD.replace("name: a", "name: b") + "      securityContext:\n        privileged: true\n"
    found = [h for h in hits(source, "k.yml") if h.rule_id == "k8s.pod.privileged"]
    assert len(found) == 1 and found[0].line > 9
    listing = "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: Pod\n    spec:\n      hostPID: true\n      containers:\n        - name: a\n"
    assert "k8s.pod.host_namespace" in ids(listing, "k.yml")


def test_file_kinds() -> None:
    assert iac_kind(".github/workflows/x.yaml") == "workflow"
    assert iac_kind("sub/action.yml") == "workflow"
    assert iac_kind("Dockerfile") == "dockerfile" and iac_kind("web/Dockerfile.dev") == "dockerfile"
    assert iac_kind("app.dockerfile") == "dockerfile" and iac_kind("Containerfile") == "dockerfile"
    assert iac_kind("infra/main.tf") == "terraform" and iac_kind("run.bash") == "shell" and iac_kind("x.sh") == "shell"
    assert iac_kind("docs/ci.yml") is None and iac_kind("docs/ci.yml", "kind: x\napiVersion: v1\n") == "kubernetes"
    assert iac_kind("a.py") is None and iac_kind("Dockerfile.md") == "dockerfile"  # a name prefix is enough


def test_suppression_with_a_reason(tmp_path: Path) -> None:
    source = '# kestrix: ignore[docker.user.root] runs under a user namespace\nFROM python:3.12\nCMD ["x"]\n'
    candidate = Candidate(path=tmp_path / "Dockerfile", rel="Dockerfile")
    findings, notes, suppressed, _ = scan_text(source, candidate)
    assert [f.rule_id for f in findings] == [] and suppressed == 1 and notes == []


def test_suppression_without_a_reason_suppresses_nothing(tmp_path: Path) -> None:
    source = "FROM python:3.12\nUSER root  # kestrix: ignore[docker.user.root]\n"
    candidate = Candidate(path=tmp_path / "Dockerfile", rel="Dockerfile")
    findings, notes, suppressed, _ = scan_text(source, candidate)
    assert "docker.user.root" in {f.rule_id for f in findings} and suppressed == 0 and len(notes) == 1


def test_workflow_suppression_inside_a_run_block(tmp_path: Path) -> None:
    source = wf(
        "      - run: |\n          # kestrix: ignore[gha.injection.untrusted_context] value is validated above\n          echo ${{ github.head_ref }}\n"
    )
    candidate = Candidate(path=tmp_path / "ci.yml", rel=WF)
    findings, _, suppressed, _ = scan_text(source, candidate)
    assert not [f for f in findings if f.rule_id.startswith("gha.")] and suppressed == 1


def test_scan_text_reports_skips_for_bad_input(tmp_path: Path) -> None:
    candidate = Candidate(path=tmp_path / "ci.yml", rel=WF)
    _, _, _, skip = scan_text("a: b\n" * 40_000, candidate)
    assert skip is not None and skip.reason == "too_complex"
    _, _, _, skip = scan_text("x: " + "[" * 100 + "\n", candidate)
    assert skip is None or skip.reason in {"too_complex", "syntax_error"}


# ----- pathological input and speed


@pytest.mark.parametrize(
    ("rel", "source"),
    [
        (WF, "on: push\njobs:\n" + "  j:\n    steps:\n" * 3000),
        (WF, "a: " + "[" * 5000 + "\n"),
        (WF, "- " * 5000 + "x\n"),
        (WF, "".join(" " * n + "k:\n" for n in range(0, 200, 2)) * 10),
        ("Dockerfile", "RUN a \\\n" * 20_000),
        ("Dockerfile", "FROM x\n" * 20_000),
        ("a.sh", "a \\\n" * 20_000),
        ("a.sh", "eval " + "$a " * 50_000 + "\n"),
        ("a.sh", "rm -rf " + '"$a" ' * 50_000 + "\n"),
        ("main.tf", 'resource "a" "b" {\n' * 5000),
        ("main.tf", "x = [" * 5000 + "\n"),
        ("main.tf", "}\n" * 20_000),
        ("main.tf", 'a = "' * 5000 + "\n"),
        (
            "k.yaml",
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n"
            + "  - name: a\n    securityContext:\n      privileged: true\n" * 2000,
        ),
    ],
    ids=[
        "jobs",
        "flow-open",
        "seq-dash",
        "indent-ladder",
        "run-cont",
        "from-many",
        "sh-cont",
        "eval-long",
        "rm-long",
        "hcl-open",
        "hcl-list",
        "hcl-close",
        "hcl-quote",
        "pods",
    ],
)
def test_pathological_input_is_bounded(rel: str, source: str) -> None:
    started = time.perf_counter()
    result = check_iac(source, rel)
    assert isinstance(result, (list, str))
    assert time.perf_counter() - started < 5


def test_speed_on_a_realistic_workflow_set() -> None:
    workflow = wf("      - uses: actions/checkout@v4\n      - run: |\n          make test\n          echo done\n" * 40)
    started = time.perf_counter()
    for _ in range(50):
        check_iac(workflow, WF)
    assert time.perf_counter() - started < 5


def test_yaml_reader_survives_empty_values_tags_and_random_text() -> None:
    import random

    for text in (
        "a: !tag\n",
        "a: &x\n",
        "- !t\n- &a\n",
        "a: [!x]\n",
        "a: {b: !x}\n",
        "a: ''\nb: \"\"\n",
        "- ''\n",
        "a: [\n",
    ):
        assert isinstance(check_iac(text, WF), list)
    rng = random.Random(7)
    alphabet = "ab:- #'\"[]{},|>&!*?\n\t\\$()=0"
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 80)))
        for rel in (WF, "Dockerfile", "x.sh", "m.tf", "k.yaml"):
            assert isinstance(
                check_iac("apiVersion: v1\nkind: Pod\n" + text if rel == "k.yaml" else text, rel), (list, str)
            )


def test_eval_indirect_expansion_idiom_is_not_reported() -> None:
    assert ids('echo "$(eval echo \\$KRA${n}_NAME)"\n', "a.sh") == set()
    assert "sh.eval.variable" in ids('eval "$cmd --flag"\n', "a.sh")


def test_rm_rf_variable_assigned_from_a_literal_or_guarded_on_the_same_line_is_not_reported() -> None:
    for script in (
        'WORKDIR=/tmp/work\nrm -rf "$WORKDIR"\n',
        'export OUT="$(mktemp -d)"\nrm -rf "$OUT"\n',
        'for d in a b; do rm -rf "$d"; done\n',
        '[[ -n "${DIR:-}" ]] && rm -rf "${DIR}"\n',
        'rm -rf "$GITHUB_WORKSPACE" "$RUNNER_TEMP" "$AGENT_TOOLSDIRECTORY"\n',
    ):
        assert "sh.rm_rf.unguarded_variable" not in ids(script, "a.sh"), script
    for script in ('DIR="$1"\nrm -rf "$DIR"\n', 'DIR=\nrm -rf "$DIR/"\n', 'rm -rf "$DIR"\n'):
        assert "sh.rm_rf.unguarded_variable" in ids(script, "a.sh"), script


def test_pipe_to_a_data_filter_is_not_remote_execution() -> None:
    for script in (
        "curl -s https://x.example/api | python3 -m json.tool\n",
        "v=$(curl -fsSL https://registry.example/x | node -p \"JSON.parse(require('fs').readFileSync(0)).v\")\n",
        "curl -s https://x.example | bash -c 'cat'\n",
        "curl -s https://x.example | jq .\n",
    ):
        assert "sh.pipe_to_shell" not in ids(script, "a.sh"), script
    for script in (
        "curl -sSL https://x.example/i.py | python3 -\n",
        "curl -sSL https://x.example/i.py | python3\n",
        "wget -qO- https://x.example | sh\n",
    ):
        assert "sh.pipe_to_shell" in ids(script, "a.sh"), script


def test_secret_tests_and_captured_echo_are_not_logged_secrets() -> None:
    for run in (
        "echo \"set: ${{ secrets.X != '' }}\"",
        'gpg --passphrase-fd 0 < <(echo "${{ secrets.PASS }}")',
        'echo "${{ secrets.PASS }}" | base64 -d > key',
    ):
        assert "gha.secrets.echoed" not in ids(wf(f"      - run: {run}\n", extra="permissions: {}\n"), WF), run


def test_from_placeholders_are_not_untagged_images() -> None:
    assert "docker.from.latest" not in ids("FROM <baseimg>\nFROM ${BASE}\nUSER 1\n", "Dockerfile")


def test_quoted_mentions_and_single_quoted_eval_text_are_not_reported() -> None:
    assert "sh.pipe_to_shell" not in ids('echo "try: curl -fsSL $REPO/i.sh | bash -s -- -d $DIR"\n', "a.sh")
    assert "sh.pipe_to_shell" in ids('echo "$(curl -fsSL https://x.example/i.sh | bash)"\n', "a.sh")
    assert "sh.eval.variable" not in ids('eval \'$EGREP -e "$re" "$f"\'\n', "a.sh")
    assert "sh.eval.variable" in ids('eval "$EGREP -e $re"\n', "a.sh")
