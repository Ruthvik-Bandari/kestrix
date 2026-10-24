# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-78): Django view runs convert directly with the source name as one argument."""

import subprocess

from django.http import JsonResponse


def thumbnail(request):
    src = request.GET["src"]
    proc = subprocess.Popen(["convert", src, "-resize", "64x64", "/tmp/thumb.png"])
    proc.wait()
    return JsonResponse({"status": proc.returncode})
