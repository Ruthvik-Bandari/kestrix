# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-614): Django stores a preferences cookie with secure=False."""

from django.http import JsonResponse


def save_prefs(request):
    response = JsonResponse({"saved": True})
    response.set_cookie("prefs", request.POST.get("theme", "light"), secure=False, httponly=True)
    return response
