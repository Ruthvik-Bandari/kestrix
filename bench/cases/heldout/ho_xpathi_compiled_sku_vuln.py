# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-643): Compiles an lxml XPath object from a SKU concatenated into the expression."""

from django.http import JsonResponse
from lxml import etree

INVENTORY = etree.parse("/srv/app/inventory.xml")


def stock(request):
    sku = request.GET["sku"]
    query = etree.XPath("//item[@sku='" + sku + "']/@count")
    return JsonResponse({"count": [str(c) for c in query(INVENTORY)]})
