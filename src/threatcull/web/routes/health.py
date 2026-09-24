# SPDX-License-Identifier: AGPL-3.0-only
"""Unauthenticated liveness check."""

from __future__ import annotations

from fastapi import APIRouter

import threatcull

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": threatcull.__version__}
