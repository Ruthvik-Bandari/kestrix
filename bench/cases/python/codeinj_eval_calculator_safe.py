# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (safe, CWE-94): Calculator endpoint that parses a literal instead of evaluating code."""

import ast

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Expression(BaseModel):
    expr: str


@app.post("/calc")
def calc(body: Expression) -> dict[str, float]:
    value = ast.literal_eval(body.expr)
    if not isinstance(value, (int, float)):
        raise ValueError("numbers only")
    return {"result": float(value)}
