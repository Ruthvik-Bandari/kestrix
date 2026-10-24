# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Rules for Terraform (``.tf``) and Kubernetes manifests (``.yml``/``.yaml`` with ``apiVersion`` and ``kind``).

Nothing is planned, applied or evaluated; a variable or expression is never resolved, so a rule fires only on a literal.

Terraform is read by a bounded line scanner (comments and here-documents removed, blocks nested by braces, ``name = value``
attributes with a value that may span lines):

- ``tf.s3.public_access``: an S3 bucket or bucket ACL with a public ``acl`` (``public-read``, ``public-read-write``,
  ``authenticated-read``), or an ``aws_s3_bucket_public_access_block`` that sets a block flag to ``false``;
- ``tf.sg.open_admin_port``: an ``aws_security_group`` ingress, ``aws_security_group_rule`` or
  ``aws_vpc_security_group_ingress_rule`` open to ``0.0.0.0/0`` or ``::/0`` on SSH, RDP, PostgreSQL, MySQL, Redis or MongoDB
  (22, 3389, 5432, 3306, 6379, 27017), or on every port;
- ``tf.storage.unencrypted``: ``encrypted = false`` or ``storage_encrypted = false`` in a resource.

Kubernetes manifests go through ``yaml_lite.py``; every mapping with a ``containers`` list is a pod spec, wherever it sits
(Pod, Deployment, CronJob, a ``List``). Files with Helm template syntax at the start of a line are skipped.

- ``k8s.pod.privileged``, ``k8s.pod.privilege_escalation``: ``privileged: true`` and ``allowPrivilegeEscalation: true``;
- ``k8s.pod.host_path``: a ``hostPath`` volume; ``k8s.pod.host_namespace``: ``hostNetwork``, ``hostPID`` or ``hostIPC`` set to true;
- ``k8s.pod.run_as_root``: ``runAsUser: 0`` or ``runAsNonRoot: false``; ``k8s.pod.no_run_as_nonroot``: a container whose pod and
  container security contexts set neither ``runAsNonRoot: true`` nor a non-zero ``runAsUser`` (low severity, low confidence).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from .models import Confidence, Severity, SkipReason, clip_snippet
from .registry import Hit
from .yaml_lite import Map, Node, Scalar, Seq, YamlError, iter_maps, load_documents

MAX_INFRA_BYTES = 512 * 1024
MAX_HCL_LINES = 30_000
MAX_HCL_DEPTH = 64
MAX_STATEMENT_LINES = 300
ADMIN_PORTS: dict[int, str] = {
    22: "SSH",
    3389: "RDP",
    5432: "PostgreSQL",
    3306: "MySQL",
    6379: "Redis",
    27017: "MongoDB",
}
_PUBLIC_ACLS = frozenset({"public-read", "public-read-write", "authenticated-read"})
_BLOCK_FLAGS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
_OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
_WORKLOADS_WITH_PODS = ("containers", "initContainers")


def _hit(
    lines: list[str],
    rule_id: str,
    line: int,
    message: str,
    *,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
) -> Hit:
    snippet = clip_snippet(lines[line - 1]) if 1 <= line <= len(lines) else ""
    return Hit(
        rule_id=rule_id,
        line=line,
        column=1,
        end_line=line,
        message=message,
        snippet=snippet,
        severity=severity,
        confidence=confidence,
    )


# ----- Terraform


@dataclass(slots=True)
class HclBlock:
    kind: str
    labels: tuple[str, ...]
    line: int
    attrs: dict[str, tuple[str, int]] = field(default_factory=dict)  # name -> (value text, line)
    children: list[HclBlock] = field(default_factory=list)


_ATTRIBUTE = re.compile(r"^([A-Za-z_][\w-]*)\s*=(?![=>])\s*(.*)$")
_BLOCK_OPEN = re.compile(r"^([A-Za-z_][\w-]*)((?:\s+(?:\"[^\"]*\"|[A-Za-z_][\w-]*))*)\s*\{\s*(.*)$")
_LABEL = re.compile(r"\"([^\"]*)\"|([A-Za-z_][\w-]*)")
_HEREDOC_START = re.compile(r"<<-?\s*([A-Za-z_]\w*)\s*$")


def _hcl_lines(text: str) -> list[tuple[int, str]]:
    """(line number, text) with comments and here-document bodies removed."""
    out: list[tuple[int, str]] = []
    in_block = False
    heredoc: str | None = None
    for no, raw in enumerate(text.splitlines()[:MAX_HCL_LINES], start=1):
        if heredoc is not None:
            if raw.strip() == heredoc:
                heredoc = None
            out.append((no, ""))
            continue
        kept: list[str] = []
        in_string = False
        i = 0
        while i < len(raw):
            char = raw[i]
            if in_block:
                end = raw.find("*/", i)
                if end == -1:
                    i = len(raw)
                else:
                    in_block = False
                    i = end + 2
                continue
            if in_string:
                kept.append(char)
                if char == "\\" and i + 1 < len(raw):
                    kept.append(raw[i + 1])
                    i += 1
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
                kept.append(char)
            elif char == "#" or raw.startswith("//", i):
                break
            elif raw.startswith("/*", i):
                in_block = True
                i += 1
            else:
                kept.append(char)
            i += 1
        line = "".join(kept).rstrip()
        match = _HEREDOC_START.search(line)
        if match is not None:
            heredoc = match.group(1)
        out.append((no, line))
    return out


def _unbalanced(text: str) -> int:
    depth = 0
    in_string = False
    i = 0
    while i < len(text):
        char = text[i]
        if in_string:
            if char == "\\":
                i += 1
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        i += 1
    return depth


def parse_hcl(text: str) -> HclBlock | SkipReason:
    """The blocks and attributes of a Terraform file under a synthetic root block."""
    root = HclBlock("", (), 0)
    stack = [root]
    rows = _hcl_lines(text)
    i = 0
    while i < len(rows):
        no, line = rows[i]
        i += 1
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("}"):
            if len(stack) > 1:
                stack.pop()
            continue
        attribute = _ATTRIBUTE.match(stripped)
        if attribute is not None:
            value = attribute.group(2)
            joined = 0
            while _unbalanced(value) > 0 and i < len(rows) and joined < MAX_STATEMENT_LINES:
                value += " " + rows[i][1].strip()
                i += 1
                joined += 1
            stack[-1].attrs.setdefault(attribute.group(1), (value.strip(), no))
            continue
        opened = _BLOCK_OPEN.match(stripped)
        if opened is not None:
            if len(stack) >= MAX_HCL_DEPTH:
                return "too_complex"
            labels = tuple(a or b for a, b in _LABEL.findall(opened.group(2)))
            block = HclBlock(opened.group(1), labels, no)
            stack[-1].children.append(block)
            rest = opened.group(3).strip()
            if rest.startswith("}"):
                continue
            if rest:  # one-line block: ``ingress { from_port = 22 }``
                for part in re.split(r"[;,]|\s+(?=[A-Za-z_][\w-]*\s*=)", rest.rstrip("}")):
                    attr = _ATTRIBUTE.match(part.strip())
                    if attr is not None:
                        block.attrs.setdefault(attr.group(1), (attr.group(2).strip(), no))
                if rest.rstrip().endswith("}"):
                    continue
            stack.append(block)
    return root


def _string(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"' and "${" not in value:
        return value[1:-1]
    return None


def _literal(value: str | None) -> str | None:
    """Text of a quoted or bare literal (``false``, ``22``, ``"tcp"``), else None."""
    if value is None:
        return None
    text = _string(value)
    if text is not None:
        return text
    value = value.strip()
    return value if re.fullmatch(r"[A-Za-z0-9_.-]+", value) else None


def _strings(value: str | None) -> list[str]:
    return re.findall(r'"([^"]*)"', value) if value is not None else []


def _attr(block: HclBlock, name: str) -> tuple[str, int] | None:
    return block.attrs.get(name)


def _walk_blocks(block: HclBlock) -> Iterator[HclBlock]:
    for child in block.children:
        yield child
        yield from _walk_blocks(child)


def _exposed_admin_ports(low: str | None, high: str | None, protocol: str | None) -> str | None:
    """Text naming the admin ports a rule opens, or None when it opens none or cannot be judged."""
    if protocol is None:
        return None
    if protocol in ("-1", "all"):
        return "every port"
    if protocol.lower() not in ("tcp", "6"):
        return None
    if low is None or high is None or not low.isdigit() or not high.isdigit():
        return None
    ports = [f"{port} ({name})" for port, name in ADMIN_PORTS.items() if int(low) <= port <= int(high)]
    return ", ".join(ports) if ports else None


def _ingress_rules(resource: HclBlock) -> Iterator[tuple[HclBlock, bool]]:
    """(block holding the ingress attributes, True) for each ingress rule of a security group resource."""
    kind = resource.labels[0] if resource.labels else ""
    if kind == "aws_security_group":
        for child in resource.children:
            if child.kind == "ingress":
                yield child, True
            elif child.kind == "dynamic" and child.labels[:1] == ("ingress",):
                yield from ((c, True) for c in child.children if c.kind == "content")
    elif kind == "aws_security_group_rule":
        if _literal((_attr(resource, "type") or ("", 0))[0]) == "ingress":
            yield resource, True
    elif kind == "aws_vpc_security_group_ingress_rule":
        yield resource, True


def _check_security_group(lines: list[str], resource: HclBlock, hits: list[Hit]) -> None:
    for rule, _ in _ingress_rules(resource):
        cidrs: list[tuple[str, int]] = []
        for name in ("cidr_blocks", "ipv6_cidr_blocks"):
            if (found := _attr(rule, name)) is not None:
                cidrs.extend((cidr, found[1]) for cidr in _strings(found[0]) if cidr in _OPEN_CIDRS)
        for name in ("cidr_ipv4", "cidr_ipv6"):
            if (found := _attr(rule, name)) is not None and _string(found[0]) in _OPEN_CIDRS:
                cidrs.append((_string(found[0]) or "", found[1]))
        if not cidrs:
            continue
        protocol = _literal((_attr(rule, "protocol") or _attr(rule, "ip_protocol") or ("", 0))[0] or None)
        ports = _exposed_admin_ports(
            _literal((_attr(rule, "from_port") or ("", 0))[0] or None),
            _literal((_attr(rule, "to_port") or ("", 0))[0] or None),
            protocol,
        )
        if ports is not None:
            cidr, line = cidrs[0]
            hits.append(
                _hit(
                    lines,
                    "tf.sg.open_admin_port",
                    line,
                    f"Ingress from {cidr} reaches {ports}, so anyone on the internet can try to connect.",
                )
            )


def _flag_hits(lines: list[str], resource: HclBlock) -> Iterator[Hit]:
    kind = resource.labels[0]
    acl = _attr(resource, "acl")
    if kind in ("aws_s3_bucket", "aws_s3_bucket_acl") and acl is not None and _string(acl[0]) in _PUBLIC_ACLS:
        yield _hit(
            lines, "tf.s3.public_access", acl[1], f"The bucket ACL is {acl[0]}, which makes objects readable by others."
        )
    if kind == "aws_s3_bucket_public_access_block":
        for flag in _BLOCK_FLAGS:
            value = _attr(resource, flag)
            if value is not None and _literal(value[0]) == "false":
                yield _hit(
                    lines, "tf.s3.public_access", value[1], f"{flag} = false turns off a guard against public buckets."
                )
    for block in (resource, *_walk_blocks(resource)):
        for name in ("encrypted", "storage_encrypted"):
            value = _attr(block, name)
            if value is not None and _literal(value[0]) == "false":
                yield _hit(lines, "tf.storage.unencrypted", value[1], f"{name} = false stores the data unencrypted.")


def check_terraform(text: str) -> list[Hit] | SkipReason:
    root = parse_hcl(text)
    if isinstance(root, str):
        return root
    lines = text.splitlines()
    hits: list[Hit] = []
    for resource in (c for c in root.children if c.kind == "resource" and c.labels):
        hits.extend(_flag_hits(lines, resource))
        if (
            resource.labels[0].startswith("aws_security_group")
            or resource.labels[0] == "aws_vpc_security_group_ingress_rule"
        ):
            _check_security_group(lines, resource, hits)
    return hits


# ----- Kubernetes


def _truthy(node: Node | None) -> bool:
    return isinstance(node, Scalar) and node.value.lower() == "true"


def _falsy(node: Node | None) -> bool:
    return isinstance(node, Scalar) and node.value.lower() == "false"


def _context(node: Node | None) -> Map | None:
    return node if isinstance(node, Map) else None


def _pod_specs(document: Map) -> Iterator[Map]:
    for candidate in iter_maps(document):
        if any(isinstance(candidate.get(name), Seq) for name in _WORKLOADS_WITH_PODS):
            yield candidate


def _is_manifest(document: Map) -> bool:
    return document.scalar("apiVersion") is not None and document.scalar("kind") is not None


def _check_pod_spec(lines: list[str], spec: Map, hits: list[Hit]) -> None:
    volumes = spec.get("volumes")
    if isinstance(volumes, Seq):
        for volume in volumes.items:
            if isinstance(volume, Map) and volume.get("hostPath") is not None:
                hits.append(
                    _hit(
                        lines,
                        "k8s.pod.host_path",
                        volume.key_line("hostPath"),
                        "A hostPath volume mounts a file or directory of the node into the pod.",
                    )
                )
    for key in ("hostNetwork", "hostPID", "hostIPC"):
        if _truthy(spec.get(key)):
            hits.append(
                _hit(
                    lines,
                    "k8s.pod.host_namespace",
                    spec.key_line(key),
                    f"{key}: true shares the node's namespace with the pod.",
                )
            )
    pod_context = _context(spec.get("securityContext"))
    containers = spec.get("containers")
    for name in _WORKLOADS_WITH_PODS:
        group = spec.get(name)
        if not isinstance(group, Seq):
            continue
        for container in group.items:
            if not isinstance(container, Map):
                continue
            context = _context(container.get("securityContext"))
            if context is not None and _truthy(context.get("privileged")):
                hits.append(
                    _hit(
                        lines,
                        "k8s.pod.privileged",
                        context.key_line("privileged"),
                        "privileged: true gives the container the node's devices and capabilities.",
                    )
                )
            if context is not None and _truthy(context.get("allowPrivilegeEscalation")):
                hits.append(
                    _hit(
                        lines,
                        "k8s.pod.privilege_escalation",
                        context.key_line("allowPrivilegeEscalation"),
                        "allowPrivilegeEscalation: true lets a process gain more privileges than its parent.",
                    )
                )
            hits.extend(_root_hits(lines, pod_context, context, container, scan_unset=group is containers))


def _root_hits(
    lines: list[str], pod: Map | None, container_context: Map | None, container: Map, *, scan_unset: bool
) -> list[Hit]:
    explicit: list[Hit] = []
    non_root = False
    for context in (pod, container_context):
        if context is None:
            continue
        user = context.scalar("runAsUser")
        if user is not None and user.value == "0":
            explicit.append(
                _hit(
                    lines,
                    "k8s.pod.run_as_root",
                    context.key_line("runAsUser"),
                    "runAsUser: 0 runs the container as root.",
                )
            )
        elif user is not None and user.value.isdigit():
            non_root = True
        if _falsy(context.get("runAsNonRoot")):
            explicit.append(
                _hit(
                    lines,
                    "k8s.pod.run_as_root",
                    context.key_line("runAsNonRoot"),
                    "runAsNonRoot: false allows the container to run as root.",
                )
            )
        elif _truthy(context.get("runAsNonRoot")):
            non_root = True
    if explicit:
        return explicit[:1]
    if scan_unset and not non_root:
        return [
            _hit(
                lines,
                "k8s.pod.no_run_as_nonroot",
                container.line,
                "Neither the pod nor this container sets runAsNonRoot: true or a non-zero runAsUser, so an image that runs "
                "as root keeps running as root.",
                severity="low",
                confidence="low",
            )
        ]
    return []


def is_kubernetes_candidate(rel: str, text: str) -> bool:
    return rel.lower().endswith((".yml", ".yaml")) and "apiVersion" in text and "kind" in text


def check_kubernetes(text: str) -> list[Hit] | SkipReason:
    if len(text.encode("utf-8", "replace")) > MAX_INFRA_BYTES:
        return "too_large"
    if re.search(r"(?m)^\s*\{\{-?\s", text):  # Helm template control lines are not YAML
        return []
    try:
        documents = load_documents(text)
    except YamlError as exc:
        return exc.reason
    except RecursionError:
        return "too_complex"
    lines = text.splitlines()
    hits: list[Hit] = []
    for document in documents:
        if isinstance(document, Map) and _is_manifest(document):
            for spec in _pod_specs(document):
                _check_pod_spec(lines, spec, hits)
    return hits
