# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Held-out case (safe, CWE-330): Shuffles quiz questions with random, which protects nothing."""

import random

from flask import Flask, jsonify

app = Flask(__name__)
QUESTIONS = ["q1", "q2", "q3", "q4"]


@app.get("/quiz")
def quiz():
    order = list(QUESTIONS)
    random.shuffle(order)
    return jsonify(order)
