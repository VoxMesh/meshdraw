"""Offline research calculations; no claim of a secure randomness source."""

from .core import (
    InputError,
    canonical_bytes,
    evaluate,
    input_hash,
    load_request_json,
    map_digest,
    plan_hash,
    quarter,
    to_utc_us,
    validate_request,
)

__all__ = [
    "InputError", "canonical_bytes", "evaluate", "input_hash",
    "load_request_json", "map_digest", "plan_hash", "quarter",
    "to_utc_us", "validate_request",
]
