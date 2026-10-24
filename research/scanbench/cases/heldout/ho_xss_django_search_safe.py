# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-79): Django HttpResponse escapes the search term before putting it in HTML."""

from django.http import HttpResponse
from django.utils.html import escape


def search(request):
    q = request.GET.get("q", "")
    return HttpResponse(f"<h1>Results for {escape(q)}</h1><p>No matches.</p>")
