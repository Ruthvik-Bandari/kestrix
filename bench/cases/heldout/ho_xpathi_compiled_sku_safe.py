# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-643): Compiles a constant lxml XPath object and passes the SKU as a variable."""

from django.http import JsonResponse
from lxml import etree

INVENTORY = etree.parse("/srv/app/inventory.xml")
STOCK = etree.XPath("//item[@sku=$sku]/@count")


def stock(request):
    sku = request.GET["sku"]
    return JsonResponse({"count": [str(c) for c in STOCK(INVENTORY, sku=sku)]})
