# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-89): Django raw cursor query with the name as a bound parameter."""

from django.db import connection
from django.http import JsonResponse


def search(request):
    name = request.GET["name"]
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM customers WHERE name = %s", [name])
        return JsonResponse({"ids": [r[0] for r in cursor.fetchall()]})
