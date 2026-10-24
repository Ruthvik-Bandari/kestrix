# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (vulnerable, CWE-601): Logout redirects to a return_to parameter unchecked."""

from flask import Flask, redirect, request

app = Flask(__name__)


@app.get("/logout")
def logout():
    return redirect(request.args["return_to"])
