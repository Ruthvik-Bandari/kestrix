# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Tiny synthetic inputs for the link and file benchmark tests; nothing here is a real URL or document.

``SENTINEL_HOST`` and ``SENTINEL_BYTES`` must never reach a feature row or a report.
"""

import csv
import io
import zipfile
from pathlib import Path

SENTINEL_HOST = "zebra-sentinel-host.example"
SENTINEL_BYTES = b"ZEBRA-SENTINEL-FILE-CONTENT"
THREADS = ("001.zip", "002.zip")
BENIGN = 40
PHISHING = 40


def phiusiil_csv() -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["FILENAME", "URL", "Domain", "label"])
    for i in range(BENIGN):
        writer.writerow([f"{i}.txt", f"https://www.benign{i}site.com", f"www.benign{i}site.com", 1])
    for i in range(PHISHING):
        writer.writerow([f"{i}.txt", f"http://paypa1-login.bad{i}host.top/verify/{i}?id={i}", "x", 0])
    writer.writerow(["d1", "http://dup.example/a", "x", 0])  # exact duplicate pair
    writer.writerow(["d2", "http://dup.example/a", "x", 0])
    writer.writerow(["n1", "http://near.example/b", "x", 0])  # near duplicate: same host and path, other scheme/query
    writer.writerow(["n2", "https://www.near.example/b?q=1", "x", 0])
    writer.writerow(["c1", "https://conflict.example/", "x", 1])  # both labels
    writer.writerow(["c2", "https://conflict.example/", "x", 0])
    writer.writerow(["s1", f"http://{SENTINEL_HOST}/login", "x", 0])
    writer.writerow(["b1", "http://", "x", 0])  # no host
    return buf.getvalue()


def pe(extra: bytes = b"") -> bytes:
    head = bytearray(0x80)
    head[:2] = b"MZ"
    head[0x3C:0x40] = (0x80).to_bytes(4, "little")
    return bytes(head) + b"PE\x00\x00" + bytes(40) + extra


def write_raw(raw: Path) -> None:
    (raw / "phiusiil").mkdir(parents=True)
    with zipfile.ZipFile(raw / "phiusiil" / "phiusiil.zip", "w") as zf:
        zf.writestr("PhiUSIIL_Phishing_URL_Dataset.csv", phiusiil_csv())
    (raw / "majestic").mkdir()
    rows = "".join(f"{i},{i},maj{i}.org,org\n" for i in range(60)) + "70,70,benign3site.com,com\n"
    (raw / "majestic" / "majestic_million.csv").write_text("GlobalRank,TldRank,Domain,TLD\n" + rows)
    (raw / "govdocs1").mkdir()
    for n, name in enumerate(THREADS):
        with zipfile.ZipFile(raw / "govdocs1" / name, "w") as zf:
            for i in range(12):
                zf.writestr(f"{n}/{n}{i:03d}.txt", f"plain text {n} {i} ".encode() * 4 + SENTINEL_BYTES)
            zf.writestr(f"{n}/{n}900.pdf", b"%PDF-1.4\n" + bytes([n]) * 50)
            zf.writestr(f"{n}/{n}901.pdf", pe(bytes([n]) * 30))  # a program named .pdf: an extension mismatch
            zf.writestr(f"{n}/{n}902.doc", b"shared content in both threads")  # kept once
            zf.writestr(f"{n}/readme/", b"")
