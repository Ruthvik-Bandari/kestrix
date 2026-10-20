# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-501): Django view stores an integer-converted cart id in the session."""

from django.http import JsonResponse


def claim_cart(request):
    request.session["cart_id"] = int(request.GET["cart"])
    return JsonResponse({"ok": True})
