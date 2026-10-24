# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-601): Django redirect only checks that the target starts with http."""

from django.http import HttpResponseRedirect


def go(request):
    target = request.GET.get("next", "/")
    if not target.startswith("http"):
        target = "/"
    return HttpResponseRedirect(target)
