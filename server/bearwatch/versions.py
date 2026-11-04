"""Loose version comparison for software versions as Windows and NVD write them.

Handles "120.0.6099.71", "23.01", "1.2.3-beta", "10.0.22631.4317". Numeric tokens compare as
numbers, text tokens as lowercase strings, and a numeric token outranks a text one so
"1.0" > "1.0beta". Missing trailing tokens count as zero, so "1.2" == "1.2.0".
"""

import re
from functools import total_ordering

_TOKEN = re.compile(r"\d+|[a-zA-Z]+")


@total_ordering
class Version:
    __slots__ = ("raw", "parts")

    def __init__(self, raw: str):
        self.raw = raw.strip()
        self.parts = tuple((0, int(t)) if t.isdigit() else (-1, t.lower()) for t in _TOKEN.findall(self.raw))

    def _padded(self, n: int) -> tuple:
        return self.parts + ((0, 0),) * (n - len(self.parts))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        n = max(len(self.parts), len(other.parts))
        return self._padded(n) == other._padded(n)

    def __lt__(self, other: "Version") -> bool:
        n = max(len(self.parts), len(other.parts))
        return self._padded(n) < other._padded(n)

    def __hash__(self) -> int:
        p = list(self.parts)
        while p and p[-1] == (0, 0):
            p.pop()
        return hash(tuple(p))

    def __repr__(self) -> str:
        return f"Version({self.raw!r})"


def is_concrete(v: str | None) -> bool:
    """NVD uses '*' for any and '-' for not applicable."""
    return bool(v) and v not in ("*", "-")


def in_range(
    version: str,
    exact: str | None = None,
    start_incl: str | None = None,
    start_excl: str | None = None,
    end_incl: str | None = None,
    end_excl: str | None = None,
) -> bool:
    """True if version satisfies an NVD cpeMatch rule."""
    v = Version(version)
    if not v.parts:
        return False
    if is_concrete(exact):
        return v == Version(exact)  # type: ignore[arg-type]
    bounded = False
    if start_incl:
        bounded = True
        if v < Version(start_incl):
            return False
    if start_excl:
        bounded = True
        if v <= Version(start_excl):
            return False
    if end_incl:
        bounded = True
        if v > Version(end_incl):
            return False
    if end_excl:
        bounded = True
        if v >= Version(end_excl):
            return False
    # A rule with version '*' and no bounds means "all versions".
    return bounded or not is_concrete(exact)
