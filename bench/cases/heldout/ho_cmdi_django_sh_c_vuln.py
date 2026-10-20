# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-78): Django view converts an image through /bin/sh -c with the source name interpolated."""

import subprocess

from django.http import JsonResponse


def thumbnail(request):
    src = request.GET["src"]
    proc = subprocess.Popen(["/bin/sh", "-c", f"convert {src} -resize 64x64 /tmp/thumb.png"])
    proc.wait()
    return JsonResponse({"status": proc.returncode})
