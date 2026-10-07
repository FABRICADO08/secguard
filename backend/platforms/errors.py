from __future__ import annotations


class EmptyModelError(ValueError):
    """An upload parsed as JSON but contains no platform model elements."""
