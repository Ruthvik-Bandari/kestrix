# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-79): Django HttpResponse echoes the search term inside HTML."""

from django.http import HttpResponse


def search(request):
    q = request.GET.get("q", "")
    return HttpResponse(f"<h1>Results for {q}</h1><p>No matches.</p>")
