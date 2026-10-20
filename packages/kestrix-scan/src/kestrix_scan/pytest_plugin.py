# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""pytest plugin: ``pytest --kestrix [--kestrix-fail-on=LEVEL]`` adds one test item that scans the rootdir.

The item fails when findings are at or above the level (default: ``[tool.kestrix]`` ``fail-on``,
else ``high``) and its failure report is the scanner's text report. Without ``--kestrix`` the plugin
only registers its two options: the scanner is not imported and nothing is scanned.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from _pytest._code.code import ExceptionInfo, TerminalRepr

ITEM_NAME = "kestrix-scan"
LEVELS = ("low", "medium", "high", "critical", "none")


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("kestrix", "kestrix-scan security checks")
    group.addoption("--kestrix", action="store_true", default=False, help="Scan the rootdir with kestrix-scan.")
    group.addoption(
        "--kestrix-fail-on",
        choices=LEVELS,
        default=None,
        help="Lowest severity that fails the kestrix-scan item. Default: [tool.kestrix] fail-on, else high.",
    )


def pytest_collection_modifyitems(session: pytest.Session, config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("kestrix"):
        items.append(KestrixItem.from_parent(session, name=ITEM_NAME))


class KestrixFindings(Exception):
    """The findings at or above the threshold, as the scanner's text report."""


class KestrixItem(pytest.Item):
    def runtest(self) -> None:
        from .analyze import exit_code, scan
        from .cli import render_text
        from .config import discover
        from .errors import Rejected

        root = Path(self.config.rootpath)
        try:
            settings = discover(root)
            report = scan([root], root=root, config=settings, fail_on=self.config.getoption("kestrix_fail_on"))
        except Rejected as exc:
            raise KestrixFindings(f"kestrix-scan: Rejected ({exc.reason.value}): {exc.detail}") from None
        if exit_code(report):
            raise KestrixFindings(render_text(report))

    def repr_failure(self, excinfo: ExceptionInfo[BaseException], style: Any = None) -> str | TerminalRepr:
        if isinstance(excinfo.value, KestrixFindings):
            return str(excinfo.value)
        return super().repr_failure(excinfo, style=style)

    def reportinfo(self) -> tuple[Path, int | None, str]:
        return self.path, None, f"{ITEM_NAME} {self.config.rootpath}"
