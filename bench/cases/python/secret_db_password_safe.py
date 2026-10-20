# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-798): Database settings that read the password from the environment."""

import os

DATABASE = {
    "host": "db.internal",
    "user": "billing",
    "password": os.environ["BILLING_DB_PASSWORD"],
    "name": "billing",
}
