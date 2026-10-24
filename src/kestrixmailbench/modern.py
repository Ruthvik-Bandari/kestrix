# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``python -m kestrixmailbench.modern COMMAND --root DIR``: false alarms of ``kestrix.mail`` on modern normal mail.

``acquire`` (transfer node) downloads public mailing-list months; ``build`` filters, deduplicates, splits by list
and adds the synthetic newsletter cohort; ``features`` analyzes dev (or the synthetic set); ``report`` writes dev
aggregates; ``diag`` writes dev-only coarse cause counts; ``variants`` measures proposed rule changes on dev through monkeypatches; ``heldout`` claims the lock
and measures the current rules once on the held-out lists. Aggregates only: no body, address or subject is stored
in any report.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .common import Layout, MailBenchError

COMMANDS = ("acquire", "build", "features", "report", "variants", "variants-report", "heldout", "diag")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="kestrixmailbench.modern", description=__doc__)
    p.add_argument("command", choices=COMMANDS)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--only", help="acquire: source (asf or gnu)")
    p.add_argument("--shard", type=int, help="features and variants: shard number")
    p.add_argument("--splits", default="dev", help="features: dev and/or synthetic (held-out only via heldout)")
    p.add_argument("--bootstrap", type=int, default=1000)
    p.add_argument("--limit", type=int, help="build: at most this many messages per file (smoke)")
    args = p.parse_args(argv)
    os.umask(0o077)
    layout = Layout(args.root)
    try:
        return _run(args, layout)
    except MailBenchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace, layout: Layout) -> int:
    if args.command == "acquire":
        from .modern_acquire import acquire

        out = acquire(layout, args.only)
        print(f"{len(out['files'])} files, {sum(f['size'] for f in out['files'])} bytes, {len(out['failed'])} failed")
        return 0
    from . import modern_run

    return modern_run.run(args, layout)


if __name__ == "__main__":
    sys.exit(main())
