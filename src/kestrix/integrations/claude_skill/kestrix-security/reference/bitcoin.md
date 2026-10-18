# Bitcoin quantum exposure reference (`kestrix bitcoin`)

Source: `src/kestrix/bitcoin/`. Kestrix only needs public addresses or hex public keys. It never asks for
private keys or seed phrases and cannot sign, send or move coins.

## Commands

```bash
kestrix bitcoin scan 1BoatSLRHtKNngkdXEeobR76b53LETtpyT bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0 --json
kestrix bitcoin scan bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq --lookup-chain --json
kestrix bitcoin migration P2WPKH --json
```

- `scan` takes up to 100 inputs and stops at the first invalid one (exit 2, `invalid_input`, naming
  `address #N`). Offline unless `--lookup-chain`.
- `--lookup-chain` sends each P2PKH, P2WPKH, P2SH and P2WSH address (and the user's IP) to mempool.space.
  P2PK and P2TR are never sent. `--testnet signet` picks signet for `tb1`/`m`/`n`/`2` addresses (default
  `testnet4`). Exit 3 when mempool.space is unavailable; there is no partial result.
- `migration TYPE` accepts `P2PK`, `P2PKH`, `P2SH`, `P2WPKH`, `P2WSH`, `P2TR` in any case.

## Risk (`results[].risk`)

| Address type | `risk` | `key_exposure` | Why |
| --- | --- | --- | --- |
| P2PK (raw public key) | `critical` | `exposed` | The public key is permanently visible on chain. |
| P2TR (Taproot, `bc1p`) | `high` | `exposed` | The address contains the tweaked output key. |
| P2PKH, P2WPKH, P2SH, P2WSH without lookup | `unknown` | `unknown` | Only a hash is visible; the key is revealed on the first spend. |
| Same, lookup shows a spend | `high` | `exposed` | The spend published the key or script. |
| Same, lookup shows no spend | `low` | `not_exposed` | Hidden until the first spend (assuming the key is not reused elsewhere). |

`summary.by_risk` counts `critical`, `high`, `low`, `unknown`. `chain_activity` (with lookup) has
`funded_outputs`, `spent_outputs`, `balance_sats`.

## Migration (`kestrix bitcoin migration TYPE --json`)

Fields: `address_type`, `urgency`, `summary`, `steps[]`, `cautions[]`.

| Type | `urgency` |
| --- | --- |
| P2PK, P2TR | `now` |
| P2PKH, P2WPKH, P2SH, P2WSH | `if_spent` (move only if spent from and still funded) |

Typical advice: send the whole balance in one transaction to a fresh, never-used P2WPKH (`bc1q`) address,
with a fee high enough to confirm quickly, then stop using the old address.

## How to explain it

- No quantum computer able to derive private keys from public keys is publicly known to exist; estimates
  of when one could are uncertain. Report exposure, not attack timelines.
- BIP-360 and other post-quantum output types are drafts, not active. Moving coins hides the key; it does
  not make them quantum-proof.
- `unknown` is not "safe": it means "exposed only if this address has ever spent".
