# Bitcoin quantum risk: measured correctness

This page reports what `kestrix bitcoin` was tested on and how it did. Everything here runs offline: `uv run python scripts/bitcoin_eval.py` rewrites [`bitcoin.json`](bitcoin.json), and `tests/bitcoin/test_bitcoin_eval.py` fails if the committed report is out of date or any case fails. The evaluation uses no network and no chain data.

**Result: 466 of 466 cases pass (100%).** 238 are official test vectors, 158 are generated from a specification, and 70 are synthetic cases for the risk categories. The evaluation found no bug in the module, so nothing was changed in `src/kestrix/bitcoin`.

**This is a correctness check, not an accuracy figure.** The risk rating is a fixed rule by address type, not a statistical estimate, so there is no error rate to measure for it. What can be wrong is parsing (an address read as the wrong type or network, or an invalid one accepted) and the mapping from type and spend history to a rating. Those are what the cases test.

## Results by category

| Category | Cases come from | Passed |
| --- | --- | --- |
| Base58 decoding | official: Bitcoin Core `base58_encode_decode.json` | 21 of 21 |
| Base58Check P2PKH and P2SH addresses (mainnet, test) | official: Bitcoin Core `key_io_valid.json` | 22 of 22 |
| Segwit v0 and v1 addresses (P2WPKH, P2WSH, P2TR; mainnet, test, regtest) | official: Bitcoin Core `key_io_valid.json` | 24 of 24 |
| Valid segwit encodings with no defined output type, which must be refused | official: Bitcoin Core `key_io_valid.json` | 8 of 8 |
| WIF private keys, which must be refused as addresses | official: Bitcoin Core `key_io_valid.json` | 16 of 16 |
| Invalid addresses | official: Bitcoin Core `key_io_invalid.json` | 70 of 70 |
| Bech32 and Bech32m strings, valid and invalid | official: BIP-173, BIP-350 | 40 of 40 |
| Valid segwit addresses decode to the published scriptPubKey | official: BIP-350 (supersedes BIP-173) | 8 of 8 |
| Invalid segwit addresses | official: BIP-173, BIP-350 | 22 of 22 |
| Taproot addresses for the BIP-341 output keys, rated `high` and `exposed` | official: BIP-341 `wallet-test-vectors.json` | 7 of 7 |
| P2SH version bytes 5 and 196 give a leading `3` and `2` and classify as P2SH (50 hashes each, including all-zero and all-ones) | generated from BIP-13 | 100 of 100 |
| Raw public keys: 50 valid secp256k1 keys (25 points, compressed and uncompressed) and 8 invalid keys | generated with pure-Python secp256k1 | 58 of 58 |
| Risk and key exposure for every address type and spend-history state, unknown cases included | synthetic, from the rules in `risk.py` | 63 of 63 |
| `scan` asks for spend history only for hash-based types on public chains, and its summary matches its results | synthetic | 4 of 4 |
| Spend-history bodies (never spent, spent in a block, spent only in the mempool) give the documented rating | synthetic bodies in the mempool.space shape, not chain data | 3 of 3 |

## Vectors and licences

Every official vector is copied verbatim; none was written for this evaluation.

| Source | Licence | Where |
| --- | --- | --- |
| Bitcoin Core `src/test/data/base58_encode_decode.json`, `key_io_valid.json`, `key_io_invalid.json` (https://github.com/bitcoin/bitcoin/tree/master/src/test/data) | MIT | `scripts/bitcoin_vectors/` |
| BIP-173 Bech32 and BIP-350 Bech32m test vectors (https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki, `bip-0350.mediawiki`) | BSD-2-Clause | `scripts/bitcoin_bip_vectors.py` |
| BIP-341 `wallet-test-vectors.json`, `scriptPubKey` section (https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json) | BSD-3-Clause | `scripts/bitcoin_vectors/bip341_scriptpubkey.json` |

BIP-13 (https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki) defines version bytes 5 and 196 and the leading characters `3` and `2`, and publishes no test vectors, so those 100 cases are generated. Bitcoin Core's `key_io_valid.json` covers real P2SH addresses.

## What the categories show

- **Classification.** Every valid P2PKH, P2SH, P2WPKH, P2WSH and P2TR address in the official lists is classified with the right type, network and key or script hash or witness program (46 of 46), and all 70 official invalid addresses and 22 invalid segwit addresses are refused.
- **A deliberate difference from Bitcoin Core.** Core accepts any valid witness version as a payment destination. Kestrix refuses a segwit address of version 1 with a program that is not 32 bytes, and versions 2 to 16, because it cannot rate an output type that is not defined, and says so in the error. These 8 official cases count as passed when refused. WIF private keys are refused too; they are not addresses.
- **Risk categories.** P2PK is `critical` and `exposed`; P2TR is `high` and `exposed`; P2PKH, P2WPKH, P2SH and P2WSH are `unknown` without a spend history, `low` and `not_exposed` if never spent from, and `high` and `exposed` if spent from, with or without a balance left. Regtest addresses stay `unknown` even when a lookup is requested.
- **The evaluation can fail.** The tests rate Taproot `low` or accept invalid addresses on purpose and require the matching categories to report failures.

## Not measured

- **Whether real addresses have spent from themselves.** That decides `low` against `high` for hash-based addresses, and it needs chain data from mempool.space or a node. The offline cases check the mapping from spend history to rating, not the history. Not measured against the real chain.
- **Key reuse across address types.** The module assumes a key is not shared with an address that was spent from; it cannot check that without chain data.
- **Anything about quantum computers.** No attack timeline or share of exposed supply is computed or claimed.
- **Lookup reliability.** The mempool.space client is tested against mock responses only. Its behavior on the live service (rate limits, outages, reorgs) is not measured.
- **The guardian's intent classification** (the optional model-backed assistant) is not evaluated here.
