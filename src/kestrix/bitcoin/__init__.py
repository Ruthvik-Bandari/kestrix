# SPDX-FileCopyrightText: 2026 Ruthvik Bandari and the BitShield (Team ACE) contributors
# SPDX-License-Identifier: Apache-2.0
"""Bitcoin address quantum-exposure scanning.

Classifies addresses and raw public keys by whether their public key is visible on the
blockchain, optionally checks spend history on mempool.space, explains each result in
plain language and gives migration steps. It never holds keys, wallets or coins.
"""
