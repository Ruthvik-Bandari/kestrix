"""Step-by-step migration plans per address type.

Plans only describe what the user does in their own wallet. Kestrix never builds,
signs or broadcasts transactions.
"""

from __future__ import annotations

from ..core.errors import Reason, Rejected
from .models import AddressType, MigrationPlan

_MOVE_STEPS = [
    "In a wallet you control, create a brand-new receiving address that has never been used. A native "
    "SegWit P2WPKH address (starts with bc1q) hides its public key until you spend from it.",
    "Send the entire balance from the old address to the new one in a single transaction, so no change "
    "comes back to the old address.",
    "Choose a fee high enough to confirm within the next few blocks: while the transaction waits, the "
    "public key it reveals is visible to everyone in the mempool.",
    "After it confirms, check that the old address is empty and stop sharing it.",
    "Do not reuse the new address once you spend from it; spending reveals its public key too.",
]

_CAUTIONS = [
    "Never enter your seed phrase or private key into a website or tool that offers to 'check' quantum "
    "risk. Kestrix only needs public addresses.",
    "No quantum computer able to derive private keys from public keys is publicly known to exist, and "
    "estimates of when one could be built vary widely.",
    "Post-quantum output types for Bitcoin, such as BIP-360 (Pay-to-Merkle-Root), are draft proposals that "
    "are not active on the network. These steps hide your public key; they do not make coins quantum-proof.",
]

_P2PK_STEP = (
    "P2PK outputs have no address, so most modern wallets cannot show them. Sweep them with software that "
    "supports raw public-key outputs, for example a Bitcoin Core wallet with a pk() or combo() descriptor."
)

_P2TR_CAUTION = (
    "Script-path-only Taproot (an unspendable internal key) does not help: the output key is still visible "
    "and its private key can still spend through the key path."
)

_HASH_SUMMARY = (
    "This type shows only a hash until coins are spent from it. If the address has never been spent from, "
    "there is no need to move now: keep the coins there, avoid partial spends and do not reuse the address. "
    "If it has been spent from and still holds coins, its key is public, so follow these steps now."
)


def plan_for(address_type: AddressType) -> MigrationPlan:
    if address_type is AddressType.P2PK:
        return MigrationPlan(
            address_type=address_type,
            urgency="now",
            summary="The public key is permanently visible on the blockchain. Move these coins to a fresh "
            "hash-based address.",
            steps=[_MOVE_STEPS[0], _P2PK_STEP, *_MOVE_STEPS[1:]],
            cautions=list(_CAUTIONS),
        )
    if address_type is AddressType.P2TR:
        return MigrationPlan(
            address_type=address_type,
            urgency="now",
            summary="A Taproot address contains its public key, so it is visible from the moment the address "
            "is shared. If quantum risk matters for these funds, move long-term savings to a fresh hash-based "
            "address. This gives up Taproot's privacy and fee benefits.",
            steps=list(_MOVE_STEPS),
            cautions=[_P2TR_CAUTION, *_CAUTIONS],
        )
    return MigrationPlan(
        address_type=address_type,
        urgency="if_spent",
        summary=_HASH_SUMMARY,
        steps=list(_MOVE_STEPS),
        cautions=list(_CAUTIONS),
    )


def parse_address_type(value: str) -> AddressType:
    """Case-insensitive address type name, raising ``Rejected(INVALID_INPUT)`` if unknown."""
    try:
        return AddressType(value.strip().upper())
    except ValueError:
        choices = ", ".join(t.value for t in AddressType)
        raise Rejected(
            Reason.INVALID_INPUT, f"unknown address type {value[:40]!r}; expected one of {choices}"
        ) from None
