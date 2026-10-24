# Licences of the test vectors in this folder

These files are copied verbatim (or, for BIP-341, trimmed to the `scriptPubKey` section) from their upstream
projects and keep their original licences. They are test data for `scripts/bitcoin_eval.py`, not Kestrix code.

## Bitcoin Core: `base58_encode_decode.json`, `key_io_valid.json`, `key_io_invalid.json`

From https://github.com/bitcoin/bitcoin/tree/master/src/test/data

The MIT License (MIT)

Copyright (c) 2009-2026 The Bitcoin Core developers
Copyright (c) 2009-2026 Bitcoin Developers

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of
the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## BIP-341: `bip341_scriptpubkey.json`

From https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json (BIP-341 is licensed
BSD-3-Clause; see the BIP's "Copyright" section). The BIP-173 and BIP-350 vectors used in
`scripts/bitcoin_bip_vectors.py` come from those BIPs, licensed BSD-2-Clause.
