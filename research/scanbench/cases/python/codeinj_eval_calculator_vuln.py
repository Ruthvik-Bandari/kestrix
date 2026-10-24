# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark case (vulnerable, CWE-94): Calculator endpoint that evaluates the submitted expression."""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Expression(BaseModel):
    expr: str


@app.post("/calc")
def calc(body: Expression) -> dict[str, float]:
    return {"result": eval(body.expr)}
