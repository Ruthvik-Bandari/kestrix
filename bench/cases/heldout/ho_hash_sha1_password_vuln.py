# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-328): Stores user passwords as unsalted SHA-1 digests."""

import hashlib


def store_password(db, user_id, password):
    digest = hashlib.sha1(password.encode()).hexdigest()
    db.execute("UPDATE users SET pw = ? WHERE id = ?", (digest, user_id))
