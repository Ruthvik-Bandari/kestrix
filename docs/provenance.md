# Provenance and authorship

Kestrix was created by **Ruthvik Bandari**. This page lists the public evidence of authorship and how anyone can
check it.

## Evidence anyone can check

| Evidence | Where | What it shows |
| --- | --- | --- |
| Copyright and license | [`LICENSE`](../LICENSE), [`NOTICE`](../NOTICE) and an SPDX header in every source file | Apache-2.0. Section 4(d) requires anyone who redistributes Kestrix to keep the NOTICE file and its attribution. |
| Attribution in every output | `generated_by: "Kestrix by Ruthvik Bandari"` in every report, export, run manifest and `/api/health`; `kestrix version`; the dashboard | Output produced by Kestrix names its author. |
| Signed history | Commits and tags signed with the author's SSH key (`git log --show-signature`) | Who made each change, and in what order. |
| Fingerprint commitment | [`provenance/commitment-2026-10-18.txt`](provenance/commitment-2026-10-18.txt) | A SHA-256 commitment to a private list of markers placed in the source on 2026-10-18. |
| Independent timestamp | [`provenance/commitment-2026-10-18.txt.ots`](provenance/commitment-2026-10-18.txt.ots) | An [OpenTimestamps](https://opentimestamps.org) proof that anchors the commitment in the Bitcoin blockchain, so its date does not depend on anyone's word. |
| Citation | [`CITATION.cff`](../CITATION.cff) | How to cite the work and its author. |

To verify the timestamp:

```bash
pip install opentimestamps-client
ots upgrade docs/provenance/commitment-2026-10-18.txt.ots   # once, after a few hours, to fetch the Bitcoin attestation
ots verify docs/provenance/commitment-2026-10-18.txt.ots
```

## How the fingerprint commitment works

On 2026-10-18 ten unique, harmless markers were written into ordinary comments across the code base. The author
keeps the list privately, together with a random salt. Only the SHA-256 of the salted list is public, and it is
timestamped.

If someone presents Kestrix code as their own, the author can reveal the salted list:

- anyone can hash it and get the published commitment;
- anyone can then find the markers in the disputed copy.

The commitment fixes the list before the copy existed, so the markers prove the copy came from this code base.

The markers change nothing about how Kestrix behaves. They are not hidden code, they collect nothing and they
contact nothing.

## Modules adapted from earlier work

- The Bitcoin module is adapted from BitShield, built by Team ACE at the MIT Bitcoin Expo 2026. Its files credit
  those contributors.
- The forensics module is adapted from CyberSafeX Detection Suite, by the same author.
