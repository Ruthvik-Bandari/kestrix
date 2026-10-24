#!/bin/bash
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Run on the transfer node: ssh explorer-xfer 'cd ~/kestrix && bash -l research/hpc/detect/fetch_engine.sh'
# Downloads the pinned Elasticsearch 8.19.3 Linux tarball, verifies it against the SHA-512 pinned
# here (not fetched alongside it), and unpacks it under scratch. The cluster has no Docker, so the
# tarball's bundled JDK runs it as a normal user inside a Slurm job.
set -euo pipefail
VERSION=8.19.3
SHA512=a313f961fdc14eed528c0d4ca1588685903aa139cff5527f018cfcc638eb74e5178e443d50eb34d5f1e409a5a23cfb25b7b1b18025d6e8cbb7d9e88f2dd7b351
DIR="/scratch/$USER/kestrix/engine"
TARBALL="elasticsearch-$VERSION-linux-x86_64.tar.gz"
mkdir -p "$DIR"
cd "$DIR"
if [ -x "elasticsearch-$VERSION/bin/elasticsearch" ]; then
  echo "engine $VERSION already unpacked in $DIR"
  exit 0
fi
curl -fsSL --retry 3 -o "$TARBALL.part" "https://artifacts.elastic.co/downloads/elasticsearch/$TARBALL"
echo "$SHA512  $TARBALL.part" | sha512sum -c -
mv "$TARBALL.part" "$TARBALL"
tar -xzf "$TARBALL"
rm "$TARBALL"
echo "engine $VERSION ready in $DIR/elasticsearch-$VERSION"
