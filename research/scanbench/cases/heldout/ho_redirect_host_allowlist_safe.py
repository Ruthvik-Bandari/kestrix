# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-601): Django redirect checks the target's host against an allowlist with urlsplit."""

from urllib.parse import urlsplit

from django.http import HttpResponseRedirect

ALLOWED_HOSTS = {"app.example.com", "docs.example.com"}


def go(request):
    target = request.GET.get("next", "/")
    if urlsplit(target).netloc not in ALLOWED_HOSTS:
        return HttpResponseRedirect("/")
    return HttpResponseRedirect(target)
