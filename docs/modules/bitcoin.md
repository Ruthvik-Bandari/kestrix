# Bitcoin quantum risk

The Bitcoin module tells you which of your addresses have a public key visible on the blockchain, and how to move coins to an address that hides it. Use it if you hold Bitcoin and want to know which coins a future quantum computer could target first, or to get migration steps for an address type. You paste public addresses or public keys. Kestrix never asks for private keys or seed phrases, and it cannot sign, send or move coins.

The threat it reports on: a large enough quantum computer running Shor's algorithm could derive a private key from its public key. No such computer is publicly known to exist, and estimates of when one might are uncertain, so the module reports exposure, not attack timelines. It is adapted from [BitShield](https://github.com/Ruthvik-Bandari/MIT-BTC-Hackathon-Team_ACE), built by Team ACE at the MIT Bitcoin Expo 2026 hackathon. Source files are under [`src/kestrix/bitcoin/`](../../src/kestrix/bitcoin/).

## Commands

| Command | Options | What it does |
| --- | --- | --- |
| `kestrix bitcoin scan ADDRESS...` | `--lookup-chain`, `--testnet testnet4\|signet` (default `testnet4`), `--json` | Assesses up to 100 addresses or hex public keys. |
| `kestrix bitcoin migration TYPE` | `--json` | Prints migration steps for `P2PK`, `P2PKH`, `P2SH`, `P2WPKH`, `P2WSH` or `P2TR` (any case). |
| `kestrix bitcoin ask MESSAGE` | `--json` | Classifies a plain-language request with your own Anthropic key. Nothing is executed. |

| Exit code | Meaning ([`cli.py`](../../src/kestrix/bitcoin/cli.py)) |
| --- | --- |
| 0 | Success. |
| 2 | Rejected input, for example an invalid address or an unknown address type. |
| 3 | An upstream service or the AI key is unavailable: `upstream_error`, `ai_key_missing`, `target_unreachable` or `target_not_allowed`. |

```text
$ kestrix bitcoin scan bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq \
    bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0 \
    0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
[UNKNOWN] bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq  (P2WPKH, mainnet)
  ...
[HIGH] bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0  (P2TR, mainnet)
  ...
[CRITICAL] 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798  (P2PK, no network)
  ...

3 scanned: critical 1, high 1, low 0, unknown 1
```

Each result is followed by a plain-language explanation and a "What to do" line, omitted here.

## Accepted inputs

Kestrix decodes addresses itself, using only the standard library ([`address.py`](../../src/kestrix/bitcoin/address.py)). The tests check the decoders against the BIP-173 and BIP-350 test vectors.

| Input | Detected as | Network |
| --- | --- | --- |
| Base58Check, version byte `0x00` (starts with `1`) | P2PKH | `mainnet` |
| Base58Check, version byte `0x05` (starts with `3`) | P2SH | `mainnet` |
| Base58Check, version `0x6F` or `0xC4` (starts with `m`, `n` or `2`) | P2PKH or P2SH | `test` |
| Bech32, witness v0, 20-byte program (`bc1q...`) | P2WPKH | from prefix |
| Bech32, witness v0, 32-byte program | P2WSH | from prefix |
| Bech32m, witness v1, 32-byte program (`bc1p...`) | P2TR | from prefix |
| Hex public key: 33 bytes starting `02`/`03`, or 65 bytes starting `04`, on the secp256k1 curve | P2PK | none |

- Bech32 prefixes are `bc` (`mainnet`), `tb` (`test`) and `bcrt` (`regtest`).
- Testnet3, testnet4 and signet share prefixes and version bytes, so they are all reported as `test`. Base58 regtest addresses are reported as `test` too.
- Checksums are verified, including the BIP-350 rule on which checksum variant goes with which witness version.
- A valid encoding of an undefined output type (for example witness v2) is refused with a warning not to send coins to it.
- Inputs over 130 characters, empty inputs and invalid addresses are refused with `invalid_input`. A scan stops at the first invalid input and names its position, such as `address #2`.

## Risk logic

The rules are in [`risk.py`](../../src/kestrix/bitcoin/risk.py).

| Type | Risk | `key_exposure` | Why |
| --- | --- | --- | --- |
| P2PK (raw public key) | `critical` | `exposed` | The public key is the lock itself, permanently visible on chain. |
| P2TR (Taproot) | `high` | `exposed` | The address contains the tweaked output key (BIP-341), not a hash. Whoever derives its private key can spend through the key path, even when the internal key is an unspendable point. |
| P2PKH, P2WPKH, P2SH, P2WSH, no lookup | `unknown` | `unknown` | Only a hash is visible. The key (or the script holding the keys) is revealed on the first spend, and without a lookup the tool cannot tell whether that has happened. |
| Same types, lookup shows a spend | `high` | `exposed` | The spend published the key or script. |
| Same types, lookup shows no spend | `low` | `not_exposed` | The key stays hidden until the first spend. This assumes the same key is not also used by another address that has been spent from. |

The recommendation follows the result:

- **Exposed with a balance:** move the remaining sats in one transaction to a fresh P2WPKH address.
- **Exposed and empty:** stop receiving to the address.
- **Unexposed:** keep the coins in place, and send the whole balance in one transaction when you do spend.

The summary counts results per risk level.

## Chain lookup and privacy

Without `--lookup-chain`, a scan makes no network requests. With it, Kestrix asks mempool.space for each hash-based address's history ([`chain.py`](../../src/kestrix/bitcoin/chain.py)):

- Only P2PKH, P2WPKH, P2SH and P2WSH addresses on `mainnet` or `test` are looked up. P2PK and P2TR results do not depend on history, so they are never sent.
- `test` addresses are looked up on testnet4 by default, or on signet with `--testnet signet`. Regtest is a private local chain, so regtest addresses are not looked up and stay `unknown`.
- The request goes to `https://mempool.space/api/address/<address>` (or the `/testnet4/` or `/signet/` path). The URL passes the same outbound check as the website check, redirects are not followed, the timeout is 10 seconds, and responses over 64 KiB are refused.
- The response must match the expected schema. Confirmed and mempool (unconfirmed) activity are added together into `funded_outputs`, `spent_outputs` and `balance_sats`.
- A rate limit (HTTP 429), a server error, an unexpected response or a network failure stops the scan with `upstream_error`. The scan does not fall back to a partial result.

**Privacy.** A lookup sends each looked-up address to mempool.space, together with your IP address. That can link the addresses to you and to each other. Leave the lookup off for addresses you do not want to disclose, or run the scan over a network you trust.

## Migration plans

`kestrix bitcoin migration TYPE` returns `address_type`, `urgency`, `summary`, `steps` and `cautions` ([`migration.py`](../../src/kestrix/bitcoin/migration.py)). Plans describe what you do in your own wallet.

| Type | `urgency` | Notes |
| --- | --- | --- |
| P2PK | `now` | Adds a step on sweeping raw public-key outputs, for example with a Bitcoin Core wallet using a `pk()` or `combo()` descriptor. |
| P2TR | `now` | Adds a caution that script-path-only Taproot does not help. Moving gives up Taproot's privacy and fee benefits. |
| P2PKH, P2WPKH, P2SH, P2WSH | `if_spent` | Move now only if the address has been spent from and still holds coins. |

Every plan cautions that BIP-360 and other post-quantum output types are draft proposals that are not active on the network. The steps hide your public key; they do not make coins quantum-proof.

## Guardian (optional, bring your own key)

The guardian turns a plain-language message, such as "is my taproot address safe?", into a suggested Kestrix command. It classifies the message and nothing else ([`guardian.py`](../../src/kestrix/bitcoin/guardian.py)).

**Setup.**

```bash
pip install "kestrix[ai]"
kestrix config set-anthropic-key    # or set ANTHROPIC_API_KEY
kestrix bitcoin ask "check 1BoatSLRHtKNngkdXEeobR76b53LETtpyT for me"
```

- **Key.** `ANTHROPIC_API_KEY` is used first, then the stored key. See [Secrets](../security-model.md#how-secrets-are-stored).
- **Model.** The default model is `claude-opus-5-5`. Set `KESTRIX_AI_MODEL` to use another model ID. The server-side refusal fallback beta is requested only for the default model.
- **Request.** One structured-output request with a 60 second timeout. The message is sent to the Anthropic API, so do not include anything you would not send there.

**Intents.**

| `intent` | Next step Kestrix suggests |
| --- | --- |
| `scan_addresses` | The exact `kestrix bitcoin scan ...` command for the validated addresses. Nothing is scanned yet. |
| `explain_risk` | A fixed explanation of which address types show keys. |
| `migration_help` | `kestrix bitcoin migration <TYPE>`, or a prompt to scan first when no type was named. |
| `set_policy_request` | A statement that Kestrix is read-only and cannot send coins or change wallet policies. |
| `unknown` | A list of what the guardian can help with. |

**What is trusted and what is not.**

- The message must be 1 to 2,000 characters after trimming.
- An address the model returns is kept only if it appears verbatim in your message and passes the local parser. Anything else goes to `ignored_addresses`. At most 100 are considered.
- `address_type` is kept only for `migration_help`.
- `next_step` is written by Kestrix, not by the model.
- `model_summary` is model-written text, cut to 500 characters. It is unverified and may be wrong. The CLI labels it "(model-written)".
- The system prompt tells the model to treat the message as data. That instruction lowers the risk of prompt injection but does not remove it. Because the model cannot trigger any action, an injected instruction can at most produce a misleading summary or intent.

**Errors.** A missing key, or a missing `[ai]` extra, gives `ai_key_missing`. A rejected key also gives `ai_key_missing`, with a prompt to set it again. API errors, connection failures and refusals give `upstream_error`. Over HTTP these are status 503 and 502.

## Measured correctness

An offline evaluation, `uv run python scripts/bitcoin_eval.py`, runs 466 cases and all 466 pass (100%). Per-category results, the vector sources with their licences and the full list of what is not measured are in [`docs/benchmarks/bitcoin.md`](../benchmarks/bitcoin.md); the machine-readable report is [`bitcoin.json`](../benchmarks/bitcoin.json), and a test fails if it goes out of date.

- **Official vectors (238 cases):** Bitcoin Core's base58 and address lists, BIP-173 and BIP-350 Bech32 and Bech32m, and the BIP-341 Taproot output keys. Every valid address gets the right type, network and payload, and every invalid address and every WIF private key is refused.
- **Generated (158 cases):** 100 P2SH addresses from BIP-13's version bytes and 58 raw secp256k1 public keys, valid and invalid.
- **Synthetic (70 cases):** the rating for every address type and spend-history state, `unknown` cases included, which addresses `scan` looks up, and how three kinds of spend-history response are rated.
- **No bug was found**, so the module is unchanged.

This is a correctness check of parsing and of the type-to-rating rule, not an accuracy rate: the rating is a fixed rule, not an estimate. **Not measured:** whether real addresses have spent from themselves (it needs chain data, and decides `low` against `high` for hash-based addresses), key reuse across address types, how the mempool.space lookup behaves on the live service, and the guardian's intent classification.

## What was not carried over from BitShield

BitShield was a hackathon project with a TypeScript stack. Kestrix ports its address scanner, risk explanations, migration planner and intent classifier, and re-implements them in Python with local validation. The following BitShield features are not part of this module:

- the Nunchuk bounded-authority group wallet, spending policies and co-signing;
- Lightning payments through Alby NWC;
- Cogcoin on-chain audit anchoring with `OP_RETURN`;
- real-time WebSocket wallet updates and the UTXO monitor;
- the quantum "attack timer" demonstration;
- BitShield's exposed-supply and attack-time figures, which Kestrix does not repeat.

One risk level also differs. BitShield's README rated Taproot as medium; Kestrix rates it `high`, because the output key is visible from the moment the address is shared.
