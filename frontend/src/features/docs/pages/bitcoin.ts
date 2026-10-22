// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { guide, list, note, p, section, see, table } from "../blocks";
import type { DocPage } from "../model";
import { HOSTED_DOC_PATH } from "../model";
import { LIMITS_NAV, ref, toolOverview } from "./helpers";

/* Follows docs/modules/bitcoin.md. The module is adapted from BitShield (MIT Bitcoin Expo 2026, Team ACE). */

const BASE = "tools/bitcoin";

export const bitcoinPages: DocPage[] = [
  toolOverview("bitcoin", BASE, [`${BASE}/how-it-works`, `${BASE}/using-it`, `${BASE}/findings`, `${BASE}/limits`]),
  {
    path: `${BASE}/how-it-works`,
    title: "Bitcoin quantum risk: how it works",
    nav: "How it works",
    summary: "Which inputs are accepted, how each address type is rated, how the optional chain lookup works and what the guardian trusts.",
    sections: [
      ref("bitcoin", "How it works"),
      section(
        "Accepted inputs",
        p("Kestrix decodes addresses itself, using only the standard library, and verifies checksums, including the BIP-350 rule on which checksum variant goes with which witness version."),
        table(
          ["Input", "Detected as", "Network"],
          [
            ["Base58Check, version byte `0x00` (starts with `1`)", "P2PKH", "`mainnet`"],
            ["Base58Check, version byte `0x05` (starts with `3`)", "P2SH", "`mainnet`"],
            ["Base58Check, version `0x6F` or `0xC4` (starts with `m`, `n` or `2`)", "P2PKH or P2SH", "`test`"],
            ["Bech32, witness v0, 20-byte program (`bc1q...`)", "P2WPKH", "from prefix"],
            ["Bech32, witness v0, 32-byte program", "P2WSH", "from prefix"],
            ["Bech32m, witness v1, 32-byte program (`bc1p...`)", "P2TR", "from prefix"],
            ["Hex public key: 33 bytes starting `02` or `03`, or 65 bytes starting `04`, on the secp256k1 curve", "P2PK", "none"],
          ],
        ),
        p("Inputs over 130 characters, empty inputs and invalid addresses are refused with `invalid_input`. A scan stops at the first invalid input and names its position. A valid encoding of an undefined output type, such as witness v2, is refused with a warning not to send coins to it."),
      ),
      section(
        "The optional chain lookup",
        p("Without `--lookup-chain`, a scan makes no network requests. With it, Kestrix asks mempool.space for each hash-based address's history."),
        list(
          "Only P2PKH, P2WPKH, P2SH and P2WSH addresses on `mainnet` or `test` are looked up. P2PK and P2TR results do not depend on history, so they are never sent.",
          "The URL passes the same outbound check as the website check, redirects are not followed, the timeout is 10 seconds, and responses over 64 KiB are refused.",
          "A rate limit, a server error, an unexpected response or a network failure stops the scan with `upstream_error`. The scan never falls back to a partial result.",
        ),
        note("A lookup sends each looked-up address to mempool.space, together with your IP address. That can link the addresses to you and to each other. Leave the lookup off for addresses you do not want to disclose.", "caution"),
      ),
      section(
        "The guardian (optional, bring your own key)",
        p("The guardian turns a plain-language message, such as \"is my taproot address safe?\", into a suggested Kestrix command. It classifies the message and nothing else."),
        list(
          "An address the model returns is kept only if it appears verbatim in your message and passes the local parser.",
          "`next_step` is written by Kestrix, not by the model. `model_summary` is model-written text, cut to 500 characters, unverified and labeled as model-written.",
          "Because the model cannot trigger any action, an injected instruction can at most produce a misleading summary or intent.",
          "Your message is sent to the Anthropic API with your own key, so do not include anything you would not send there.",
        ),
      ),
    ],
  },
  {
    path: `${BASE}/using-it`,
    title: "Bitcoin quantum risk: using it",
    nav: "Using it",
    summary: "Scan addresses, get migration steps and use the guardian, in the dashboard or with `kestrix bitcoin`.",
    sections: [
      section(
        "In the dashboard",
        p("Paste public addresses or public keys (up to 100), choose whether to look up the chain, and read the risk for each. Each result has a plain-language explanation and a \"What to do\" line, and migration steps are available for each address type. The page says before it sends anything off your computer that a lookup does so."),
        p("The Bitcoin page runs on your own computer only. On the hosted service the page is a guide to running it locally."),
        see("What the hosted service runs", HOSTED_DOC_PATH),
      ),
      section("On the command line", guide("bitcoin")),
      section(
        "Commands and exit codes",
        table(
          ["Command", "Options", "What it does"],
          [
            ["`kestrix bitcoin scan ADDRESS...`", "`--lookup-chain`, `--testnet testnet4|signet` (default `testnet4`), `--json`", "Assesses up to 100 addresses or hex public keys."],
            ["`kestrix bitcoin migration TYPE`", "`--json`", "Prints migration steps for `P2PK`, `P2PKH`, `P2SH`, `P2WPKH`, `P2WSH` or `P2TR` (any case)."],
            ["`kestrix bitcoin ask MESSAGE`", "`--json`", "Classifies a plain-language request with your own Anthropic key. Nothing is executed."],
          ],
        ),
        table(
          ["Exit code", "Meaning"],
          [
            ["0", "Success."],
            ["2", "Rejected input, for example an invalid address or an unknown address type."],
            ["3", "An upstream service or the AI key is unavailable: `upstream_error`, `ai_key_missing`, `target_unreachable` or `target_not_allowed`."],
          ],
        ),
      ),
      section(
        "Migration plans",
        p("`kestrix bitcoin migration TYPE` returns the address type, an urgency, a summary, steps and cautions. Plans describe what you do in your own wallet. Kestrix never signs, sends or moves coins."),
        table(
          ["Type", "urgency", "Notes"],
          [
            ["P2PK", "`now`", "Adds a step on sweeping raw public-key outputs."],
            ["P2TR", "`now`", "Adds a caution that script-path-only Taproot does not help. Moving gives up Taproot's privacy and fee benefits."],
            ["P2PKH, P2WPKH, P2SH, P2WSH", "`if_spent`", "Move now only if the address has been spent from and still holds coins."],
          ],
        ),
        p("Every plan cautions that BIP-360 and other post-quantum output types are draft proposals that are not active on the network. The steps hide your public key; they do not make coins quantum-proof."),
      ),
    ],
  },
  {
    path: `${BASE}/findings`,
    title: "Bitcoin quantum risk: findings reference",
    nav: "Findings reference",
    summary: "How each address type is rated, what the recommendation says and what the guardian's intents mean.",
    sections: [
      section(
        "Risk by address type",
        table(
          ["Type", "Risk", "key_exposure", "Why"],
          [
            ["P2PK (raw public key)", "`critical`", "`exposed`", "The public key is the lock itself, permanently visible on chain."],
            ["P2TR (Taproot)", "`high`", "`exposed`", "The address contains the tweaked output key, not a hash. Whoever derives its private key can spend through the key path."],
            ["P2PKH, P2WPKH, P2SH, P2WSH, no lookup", "`unknown`", "`unknown`", "Only a hash is visible. The key (or the script holding the keys) is revealed on the first spend, and without a lookup the tool cannot tell whether that has happened."],
            ["Same types, lookup shows a spend", "`high`", "`exposed`", "The spend published the key or script."],
            ["Same types, lookup shows no spend", "`low`", "`not_exposed`", "The key stays hidden until the first spend. This assumes the same key is not also used by another address that has been spent from."],
          ],
        ),
      ),
      section(
        "Recommendations",
        list(
          "Exposed with a balance: move the remaining sats in one transaction to a fresh P2WPKH address.",
          "Exposed and empty: stop receiving to the address.",
          "Unexposed: keep the coins in place, and send the whole balance in one transaction when you do spend.",
        ),
        p("The summary counts results per risk level."),
      ),
      section(
        "Guardian intents",
        table(
          ["intent", "Next step Kestrix suggests"],
          [
            ["`scan_addresses`", "The exact `kestrix bitcoin scan ...` command for the validated addresses. Nothing is scanned yet."],
            ["`explain_risk`", "A fixed explanation of which address types show keys."],
            ["`migration_help`", "`kestrix bitcoin migration <TYPE>`, or a prompt to scan first when no type was named."],
            ["`set_policy_request`", "A statement that Kestrix is read-only and cannot send coins or change wallet policies."],
            ["`unknown`", "A list of what the guardian can help with."],
          ],
        ),
        p("A missing key, or a missing `ai` extra, gives `ai_key_missing`; so does a rejected key. API errors, connection failures and refusals give `upstream_error`."),
      ),
    ],
  },
  {
    path: `${BASE}/limits`,
    title: "Bitcoin quantum risk: limits and measured accuracy",
    nav: LIMITS_NAV,
    summary: "What the quantum-risk check does not claim, what was tested, and what was not carried over from BitShield.",
    sections: [
      ref("bitcoin", "Limits"),
      section(
        "Measured accuracy",
        p("Not measured as an accuracy figure. The risk rating is a fixed rule by address type, not a statistical estimate. The address decoders are tested against the BIP-173 and BIP-350 test vectors."),
        p("No quantum computer able to break a Bitcoin key is publicly known to exist, and estimates of when one might are uncertain, so the module reports exposure, not attack timelines."),
      ),
      section(
        "What was not carried over from BitShield",
        p("The module is adapted from BitShield, built by Team ACE at the MIT Bitcoin Expo 2026 hackathon. Kestrix ports its address scanner, risk explanations, migration planner and intent classifier, and re-implements them in Python with local validation. These BitShield features are not part of this module:"),
        list(
          "the Nunchuk bounded-authority group wallet, spending policies and co-signing;",
          "Lightning payments through Alby NWC;",
          "Cogcoin on-chain audit anchoring with `OP_RETURN`;",
          "real-time WebSocket wallet updates and the UTXO monitor;",
          "the quantum \"attack timer\" demonstration;",
          "BitShield's exposed-supply and attack-time figures, which Kestrix does not repeat.",
        ),
        p("One risk level also differs: BitShield's README rated Taproot as medium; Kestrix rates it `high`, because the output key is visible from the moment the address is shared."),
      ),
    ],
  },
];
