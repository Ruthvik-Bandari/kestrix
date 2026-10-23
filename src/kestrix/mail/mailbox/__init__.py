# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Local-mode-only, read-only Gmail and Microsoft 365 connector (ADR 0009).

The user brings their own OAuth app, picks single messages from a list, and each pick is analysed in memory by
`kestrix.mail.analyze`. The hosted service does not register these routes.
"""

from .service import MailboxService

__all__ = ["MailboxService"]
