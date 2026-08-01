"""Safe CSV projection helpers.

Canonical JSON must retain the original value. Only a spreadsheet-facing CSV
projection is neutralized.
"""

from __future__ import annotations

import math
from typing import Any

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def spreadsheet_safe_cell(value: Any) -> str:
    """Return a spreadsheet-safe text projection of *value*.

    A leading apostrophe is the conventional display-preserving neutralizer
    for spreadsheet formulas. The caller must keep the unmodified value in
    canonical JSON.
    """

    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("CSV values cannot contain NaN or Infinity")
        return str(value)
    text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text
