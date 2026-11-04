"""JSON read from untrusted text, with integer literals bounded the same on every Python.

json.loads converts an integer literal with int(): quadratic in its digits on Python 3.9
(a 512 Ki-digit one took 2.6 s), and refused over 4300 digits on 3.11+. loads() refuses
one over that length (ValueError, like any text that is not JSON) before converting it,
so a hostile file or server line costs linear time on every version. Readers that never
use the numbers (the scan surfaces) pass parse_int=str instead and read the rest.
"""
from __future__ import annotations

import json

MAX_INT_DIGITS = 4300  # Python 3.11+'s default (sys.get_int_max_str_digits)


def _int(literal: str) -> int:
    if len(literal.lstrip("-")) > MAX_INT_DIGITS:
        raise ValueError(f"integer literal of {len(literal)} characters")
    return int(literal)


def loads(text: str) -> object:
    """json.loads(text), raising ValueError for an integer literal of over MAX_INT_DIGITS digits."""
    return json.loads(text, parse_int=_int)
