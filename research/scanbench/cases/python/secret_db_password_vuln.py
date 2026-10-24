# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-798): Database settings with the password written into the source."""

DATABASE = {
    "host": "db.internal",
    "user": "billing",
    "password": "Vq8!rT2#mZ6pLx4@Nw9s",
    "name": "billing",
}
