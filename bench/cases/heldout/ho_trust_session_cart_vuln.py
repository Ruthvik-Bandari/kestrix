# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-501): Django view stores a query parameter in the session as the cart owner."""

from django.http import JsonResponse


def claim_cart(request):
    request.session["cart_owner"] = request.GET.get("owner")
    return JsonResponse({"ok": True})
