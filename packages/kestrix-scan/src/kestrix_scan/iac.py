# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Infrastructure-as-code and CI files: which checker reads a file, chosen by its path (and, for YAML, its content).

- GitHub Actions workflows and composite actions: ``ci_rules.py`` (``gha.*``);
- Dockerfiles and Containerfiles: ``docker_rules.py`` (``docker.*``);
- ``.sh`` and ``.bash`` scripts: ``shell_rules.py`` (``sh.*``);
- ``.tf`` files and Kubernetes manifests: ``infra_rules.py`` (``tf.*``, ``k8s.*``).

Suppression works as in every other file: ``# kestrix: ignore[rule-id] reason`` on the finding's line or the line above.
"""

from __future__ import annotations

from .ci_rules import check_workflow, is_workflow
from .docker_rules import check_dockerfile, is_dockerfile
from .infra_rules import check_kubernetes, check_terraform, is_kubernetes_candidate
from .models import SkipReason
from .registry import Hit
from .shell_rules import check_shell


def iac_kind(rel: str, text: str = "") -> str | None:
    """'workflow', 'dockerfile', 'shell', 'terraform' or 'kubernetes' for a file these rules read, else None.

    ``text`` is needed only to tell a Kubernetes manifest from other YAML; without it YAML is not claimed.
    """
    lower = rel.lower()
    if is_workflow(rel):
        return "workflow"
    if is_dockerfile(rel):
        return "dockerfile"
    if lower.endswith(".tf"):
        return "terraform"
    if lower.endswith((".sh", ".bash")):
        return "shell"
    if text and is_kubernetes_candidate(rel, text):
        return "kubernetes"
    return None


def check_iac(text: str, rel: str) -> list[Hit] | SkipReason:
    """Rule hits for one infrastructure or CI file, or why it could not be analyzed."""
    kind = iac_kind(rel, text)
    if kind == "workflow":
        return check_workflow(text, rel)
    if kind == "dockerfile":
        return check_dockerfile(text)
    if kind == "terraform":
        return check_terraform(text)
    if kind == "shell":
        return check_shell(text)
    if kind == "kubernetes":
        return check_kubernetes(text)
    return []
