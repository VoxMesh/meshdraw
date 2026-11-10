"""Deterministic offline research core using explicit, untrusted inputs only.

Reproducibility does not establish RF authenticity, completeness, entropy, or
resistance to an organiser choosing the input. This is not stage-7 compatibility.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from fractions import Fraction
import hashlib
import json
import re
import struct


SCHEMA_VERSION = "meshdraw-core-v0.2"
RESULT_VERSION = "meshdraw-result-v0.2"
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_CANONICAL_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 200000
MAX_ROWS = 10000
I64_MIN = -(2 ** 63)
I64_MAX = 2 ** 63 - 1
ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z", re.ASCII)
DECIMAL_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z", re.ASCII)
TICKET_RE = re.compile(r"[0-9]{1,32}\Z", re.ASCII)
ISO_RE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?"
    r"(Z|[+-][0-9]{2}:[0-9]{2})\Z", re.ASCII,
)

REQUEST_KEYS = {"schema_version", "draw_id", "tickets", "rules", "source", "observations"}
RULE_KEYS = {
    "candidate", "candidate_version", "canonicalization", "start_us", "end_us",
    "delivery_deadline_us", "allowed_observers", "event_type", "direction",
    "retained_policy", "rssi_min", "rssi_max", "snr_min", "snr_max",
    "quantization", "dedup_policy", "ambiguity_policy", "min_rows",
    "min_observers", "mapping_max_words",
}
SOURCE_KEYS = {
    "dataset_id", "adapter_version", "region", "rssi_unit", "snr_unit",
    "time_unit", "provenance", "limitations",
}
ROW_KEYS = {
    "record_id", "seq", "observer_id", "packet_id", "event_type", "direction",
    "retained", "source_time_us", "received_time_us", "rssi", "snr",
}
RULE_LITERALS = {
    "candidate": "DEDUP_HASH", "candidate_version": "core-v0.2",
    "canonicalization": "ascii-json-v0.2", "event_type": "PACKET",
    "direction": "RX", "retained_policy": "exclude",
    "quantization": "quarter-half-even",
    "dedup_policy": "observer-packet-earliest-source-received-seq",
    "ambiguity_policy": "retain-and-report",
}
EXCLUSION_REASONS = (
    "WRONG_EVENT", "RETAINED", "OBSERVER_NOT_ALLOWED", "OUTSIDE_WINDOW",
    "LATE_DELIVERY", "MISSING_FIELD", "OUT_OF_RANGE",
)
RF_PREFIX = b"MeshDraw-core-v0.2/DEDUP_HASH\x00"
MAP_PREFIX = b"MeshDraw-core-map-v0.2\x00"


class InputError(Exception):
    """Safe structured failure; it does not include the offending input value."""

    def __init__(self, code, field="", status="INVALID_INPUT"):
        self.status = status
        self.code = code
        self.field = field
        super().__init__(f"{status}: {code}" + (f" ({field})" if field else ""))


def _error(code, field=""):
    raise InputError(code, field)


def _object(value, keys, field):
    if type(value) is not dict:
        _error("EXPECTED_OBJECT", field)
    if set(value) != keys:
        _error("OBJECT_FIELDS", field)


def _integer(value, low, high, field):
    if type(value) is not int or not low <= value <= high:
        _error("INTEGER_RANGE", field)


def _id(value, field):
    if type(value) is not str or ID_RE.fullmatch(value) is None:
        _error("INVALID_IDENTIFIER", field)


def _decimal_fraction(text, field="value", max_length=32):
    if (type(text) is not str or len(text) > max_length
            or DECIMAL_RE.fullmatch(text) is None):
        _error("INVALID_DECIMAL", field)
    negative = text.startswith("-")
    unsigned = text[1:] if negative else text
    whole, dot, tail = unsigned.partition(".")
    scale = 10 ** len(tail) if dot else 1
    numerator = int(whole) * scale + (int(tail) if tail else 0)
    return Fraction(-numerator if negative else numerator, scale)


def quarter(text):
    """Round a decimal string to integer quarter units, exact ties to even."""
    value = _decimal_fraction(text) * 4
    magnitude, remainder = divmod(abs(value.numerator), value.denominator)
    twice = 2 * remainder
    if twice > value.denominator or (twice == value.denominator and magnitude % 2):
        magnitude += 1
    return -magnitude if value.numerator < 0 else magnitude


def to_utc_us(value, unit):
    """Convert explicit epoch units or zoned ISO-8601 exactly to signed i64 us.

    Fractions finer than a microsecond are accepted only if the trailing digits
    are zero. Floats, inferred units, naive timestamps and leap seconds fail.
    """
    units = {
        "s": 1000000, "ms": 1000, "us": 1,
        "utc-epoch-s": 1000000, "utc-epoch-ms": 1000, "utc-epoch-us": 1,
    }
    if unit == "iso8601":
        if type(value) is not str or len(value) > 256:
            _error("INVALID_TIME", "value")
        match = ISO_RE.fullmatch(value)
        if match is None:
            _error("INVALID_TIME", "value")
        year, month, day, hour, minute, second = map(int, match.groups()[:6])
        digits, zone = match.group(7) or "", match.group(8)
        if any(c != "0" for c in digits[6:]):
            _error("UNSUPPORTED_PRECISION", "value")
        micros = int((digits[:6] + "000000")[:6])
        try:
            if zone == "Z":
                tz = timezone.utc
            else:
                zh, zm = int(zone[1:3]), int(zone[4:6])
                if zh > 23 or zm > 59:
                    _error("INVALID_TIME", "value")
                offset = timedelta(hours=zh, minutes=zm)
                tz = timezone(offset if zone[0] == "+" else -offset)
            stamp = datetime(year, month, day, hour, minute, second, micros, tzinfo=tz)
            delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
            result = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
        except (ValueError, OverflowError):
            _error("INVALID_TIME", "value")
    elif type(unit) is str and unit in units:
        if type(value) is int:
            result = value * units[unit]
        elif units[unit] == 1:
            _error("EXPECTED_INTEGER", "value")
        else:
            number = _decimal_fraction(value, "value", max_length=256) * units[unit]
            if number.denominator != 1:
                _error("UNSUPPORTED_PRECISION", "value")
            result = number.numerator
    else:
        _error("INVALID_TIME_UNIT", "unit")
    _integer(result, I64_MIN, I64_MAX, "value")
    return result


def _check_json_object(obj, max_bytes=MAX_CANONICAL_BYTES):
    """Bound a JSON tree, including direct Python objects, before serialising."""
    nodes = 0
    size = 0
    active = set()

    def add(amount):
        nonlocal size
        size += amount
        if size > max_bytes:
            _error("JSON_TOO_LARGE")

    def string_size(text):
        if not text.isascii():
            _error("NON_ASCII_JSON")
        if len(text) > max_bytes:
            _error("JSON_TOO_LARGE")
        return len(json.dumps(text, ensure_ascii=True))

    def walk(value, depth):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES:
            _error("JSON_NODE_LIMIT")
        if depth > MAX_JSON_DEPTH:
            _error("JSON_DEPTH")
        if value is None:
            add(4)
        elif type(value) is bool:
            add(4 if value else 5)
        elif type(value) is int:
            if not -(10 ** 19) < value < 10 ** 20:
                _error("JSON_INTEGER_LENGTH")
            add(len(str(value)))
        elif type(value) is str:
            add(string_size(value))
        elif type(value) in (list, dict):
            identity = id(value)
            if identity in active:
                _error("JSON_CYCLE")
            active.add(identity)
            add(2 + max(0, len(value) - 1))
            if type(value) is list:
                for item in value:
                    walk(item, depth + 1)
            else:
                for key, item in value.items():
                    if type(key) is not str:
                        _error("INVALID_JSON_KEY")
                    nodes += 1
                    if nodes > MAX_JSON_NODES:
                        _error("JSON_NODE_LIMIT")
                    add(string_size(key) + 1)
                    walk(item, depth + 1)
            active.remove(identity)
        else:
            _error("INVALID_JSON_TYPE")

    walk(obj, 0)
    return size


def canonical_bytes(obj):
    """Canonical ASCII-only JSON object representation, encoded as UTF-8."""
    try:
        _check_json_object(obj)
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        _error("INVALID_JSON")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _error("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_json_number(_text):
    _error("NON_INTEGER_JSON_NUMBER")


def _json_integer(text):
    if len(text) > 20:
        _error("JSON_INTEGER_LENGTH")
    return int(text)


def load_request_json(data):
    if type(data) is not bytes:
        _error("EXPECTED_BYTES")
    if len(data) > MAX_REQUEST_BYTES:
        _error("REQUEST_TOO_LARGE")
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                         parse_int=_json_integer, parse_float=_reject_json_number,
                         parse_constant=_reject_json_number)
        _check_json_object(obj, max_bytes=MAX_REQUEST_BYTES)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        _error("INVALID_JSON")
    if type(obj) is not dict:
        _error("EXPECTED_OBJECT")
    return obj


def _validate_tickets(tickets):
    if type(tickets) is not list or not 2 <= len(tickets) <= MAX_ROWS:
        _error("TICKET_COUNT", "tickets")
    seen = set()
    for i, ticket in enumerate(tickets):
        field = f"tickets[{i}]"
        if type(ticket) is not str or TICKET_RE.fullmatch(ticket) is None:
            _error("INVALID_TICKET", field)
        numeric = int(ticket)
        if numeric in seen:
            _error("DUPLICATE_TICKET", field)
        seen.add(numeric)


def validate_request(req):
    """Validate the entire structure before filtering any observations."""
    _check_json_object(req, max_bytes=MAX_REQUEST_BYTES)
    _object(req, REQUEST_KEYS, "request")
    if req["schema_version"] != SCHEMA_VERSION:
        _error("SCHEMA_VERSION", "schema_version")
    _id(req["draw_id"], "draw_id")
    _validate_tickets(req["tickets"])
    rules = req["rules"]
    _object(rules, RULE_KEYS, "rules")
    for name, expected in RULE_LITERALS.items():
        if type(rules[name]) is not str or rules[name] != expected:
            _error("UNSUPPORTED_RULE", f"rules.{name}")
    for name in ("start_us", "end_us", "delivery_deadline_us"):
        _integer(rules[name], I64_MIN, I64_MAX, f"rules.{name}")
    if rules["start_us"] >= rules["end_us"]:
        _error("EMPTY_WINDOW", "rules.end_us")
    if rules["delivery_deadline_us"] < rules["end_us"]:
        _error("INVALID_DEADLINE", "rules.delivery_deadline_us")
    observers = rules["allowed_observers"]
    if type(observers) is not list or not 1 <= len(observers) <= MAX_ROWS:
        _error("OBSERVER_COUNT", "rules.allowed_observers")
    seen_observers = set()
    for i, observer in enumerate(observers):
        field = f"rules.allowed_observers[{i}]"
        _id(observer, field)
        if observer in seen_observers:
            _error("DUPLICATE_OBSERVER", field)
        seen_observers.add(observer)
    for name in ("min_rows", "min_observers"):
        _integer(rules[name], 1, MAX_ROWS, f"rules.{name}")
    _integer(rules["mapping_max_words"], 1, 1024, "rules.mapping_max_words")
    for metric in ("rssi", "snr"):
        low = _decimal_fraction(rules[f"{metric}_min"], f"rules.{metric}_min")
        high = _decimal_fraction(rules[f"{metric}_max"], f"rules.{metric}_max")
        if not -1000000 <= low <= high <= 1000000:
            _error("METRIC_BOUNDS", f"rules.{metric}_min")
    source = req["source"]
    _object(source, SOURCE_KEYS, "source")
    for name in ("dataset_id", "adapter_version", "region", "provenance"):
        _id(source[name], f"source.{name}")
    for name, expected in (("rssi_unit", "dBm"), ("snr_unit", "dB"),
                           ("time_unit", "utc-epoch-us")):
        if source[name] != expected:
            _error("UNSUPPORTED_UNIT", f"source.{name}")
    limitations = source["limitations"]
    if type(limitations) is not list or len(limitations) > 16:
        _error("LIMITATION_COUNT", "source.limitations")
    for i, limitation in enumerate(limitations):
        _id(limitation, f"source.limitations[{i}]")
    rows = req["observations"]
    if type(rows) is not list or len(rows) > MAX_ROWS:
        _error("ROW_COUNT", "observations")
    seen_ids, seen_sequences = set(), set()
    for i, row in enumerate(rows):
        prefix = f"observations[{i}]"
        _object(row, ROW_KEYS, prefix)
        for name in ("record_id", "observer_id", "packet_id", "event_type", "direction"):
            _id(row[name], f"{prefix}.{name}")
        _integer(row["seq"], 0, I64_MAX, f"{prefix}.seq")
        if type(row["retained"]) is not bool:
            _error("EXPECTED_BOOLEAN", f"{prefix}.retained")
        for name in ("source_time_us", "received_time_us"):
            if row[name] is not None:
                _integer(row[name], I64_MIN, I64_MAX, f"{prefix}.{name}")
        for name in ("rssi", "snr"):
            if row[name] is not None:
                _decimal_fraction(row[name], f"{prefix}.{name}")
        if row["record_id"] in seen_ids:
            raise InputError("DUPLICATE_RECORD_ID", f"{prefix}.record_id", "CONFLICTING_INPUT")
        if row["seq"] in seen_sequences:
            raise InputError("DUPLICATE_SEQUENCE", f"{prefix}.seq", "CONFLICTING_INPUT")
        seen_ids.add(row["record_id"])
        seen_sequences.add(row["seq"])


def _hash(obj):
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def plan_hash(req):
    validate_request(req)
    return _hash({name: req[name] for name in (
        "schema_version", "draw_id", "tickets", "rules", "source",
    )})


def input_hash(req):
    validate_request(req)
    return _hash(req)


def _mapping_word(root, index):
    if index == 0:
        return root
    return hashlib.sha256(MAP_PREFIX + root + struct.pack(">I", index)).digest()


def map_digest(root, tickets, max_words):
    if type(root) is not bytes or len(root) != 32:
        _error("INVALID_DIGEST", "root")
    _validate_tickets(tickets)
    _integer(max_words, 1, 1024, "max_words")
    count = len(tickets)
    limit = (2 ** 256 // count) * count
    for index in range(max_words):
        word_bytes = _mapping_word(root, index)
        if type(word_bytes) is not bytes or len(word_bytes) != 32:
            _error("INVALID_MAPPING_WORD", "mapping")
        word = int.from_bytes(word_bytes, "big")
        if word < limit:
            selected = word % count
            return {"index": selected, "ticket": tickets[selected], "words_used": index + 1}
    return {"index": None, "ticket": None, "words_used": max_words}


def _select(rows, rules):
    bounds = {metric: (
        _decimal_fraction(rules[f"{metric}_min"]),
        _decimal_fraction(rules[f"{metric}_max"]),
    ) for metric in ("rssi", "snr")}
    observers = set(rules["allowed_observers"])
    accepted, excluded = [], []
    for row in sorted(rows, key=lambda r: r["seq"]):
        reasons = []
        if row["event_type"] != rules["event_type"] or row["direction"] != rules["direction"]:
            reasons.append("WRONG_EVENT")
        if row["retained"]:
            reasons.append("RETAINED")
        if row["observer_id"] not in observers:
            reasons.append("OBSERVER_NOT_ALLOWED")
        source_time, received_time = row["source_time_us"], row["received_time_us"]
        if source_time is not None and not rules["start_us"] <= source_time < rules["end_us"]:
            reasons.append("OUTSIDE_WINDOW")
        if received_time is not None and received_time > rules["delivery_deadline_us"]:
            reasons.append("LATE_DELIVERY")
        if any(row[name] is None for name in ("source_time_us", "received_time_us", "rssi", "snr")):
            reasons.append("MISSING_FIELD")
        if any(row[metric] is not None and not bounds[metric][0] <= _decimal_fraction(row[metric]) <= bounds[metric][1]
               for metric in ("rssi", "snr")):
            reasons.append("OUT_OF_RANGE")
        if reasons:
            excluded.append({"record_id": row["record_id"], "seq": row["seq"], "reasons": reasons})
        else:
            accepted.append(row)
    return accepted, excluded


def _ambiguities(accepted):
    groups = defaultdict(list)
    for row in accepted:
        groups[(row["observer_id"], row["packet_id"], row["source_time_us"])].append(row)
    result = []
    for (observer, packet, stamp), rows in sorted(groups.items()):
        distinct = {(_decimal_fraction(row["rssi"]), _decimal_fraction(row["snr"])) for row in rows}
        if len(distinct) > 1:
            result.append({"observer_id": observer, "packet_id": packet,
                           "source_time_us": stamp,
                           "record_ids": [row["record_id"] for row in rows]})
    return result


def _deduplicate(accepted):
    groups = defaultdict(list)
    for row in accepted:
        groups[(row["observer_id"], row["packet_id"])].append(row)
    selected, representatives = [], []
    for (observer, packet), rows in sorted(groups.items()):
        winner = min(rows, key=lambda r: (r["source_time_us"], r["received_time_us"], r["seq"]))
        selected.append(winner)
        representatives.append({"observer_id": observer, "packet_id": packet,
                                "selected_record_id": winner["record_id"],
                                "record_ids": [row["record_id"] for row in rows]})
    selected.sort(key=lambda r: (r["source_time_us"], r["observer_id"], r["packet_id"], r["seq"]))
    return selected, representatives


def evaluate(req):
    """Return DRAW or NO_DRAW without modifying the request or doing I/O."""
    validate_request(req)
    rules = req["rules"]
    accepted, excluded = _select(req["observations"], rules)
    observer_count = len({row["observer_id"] for row in accepted})
    result = {
        "schema_version": RESULT_VERSION, "status": "NO_DRAW", "reason": None,
        "plan_sha256": _hash({name: req[name] for name in (
            "schema_version", "draw_id", "tickets", "rules", "source",
        )}), "input_sha256": _hash(req),
        "counts": {"input_rows": len(req["observations"]), "accepted_rows": len(accepted),
                   "excluded_rows": len(excluded), "accepted_observers": observer_count,
                   "selected_rows": None, "selected_observers": None},
        "selection": {"accepted_record_ids": [row["record_id"] for row in accepted],
                      "excluded": excluded, "representatives": None, "selected_record_ids": None},
        "diagnostics": {"ambiguous_groups": _ambiguities(accepted)},
        "rf": None, "mapping": None,
    }
    if len(accepted) < rules["min_rows"] or observer_count < rules["min_observers"]:
        result["reason"] = "INSUFFICIENT_ROWS_OR_OBSERVERS"
        return result
    selected, representatives = _deduplicate(accepted)
    selected_observers = len({row["observer_id"] for row in selected})
    result["selection"]["representatives"] = representatives
    result["selection"]["selected_record_ids"] = [row["record_id"] for row in selected]
    result["counts"].update(selected_rows=len(selected), selected_observers=selected_observers)
    if len(selected) < rules["min_rows"] or selected_observers < rules["min_observers"]:
        result["reason"] = "INSUFFICIENT_DEDUP_ROWS_OR_OBSERVERS"
        return result
    pairs = [[quarter(row["rssi"]), quarter(row["snr"])] for row in selected]
    rf_bytes = RF_PREFIX + struct.pack(">I", len(pairs)) + b"".join(
        struct.pack(">ii", *pair) for pair in pairs)
    digest = hashlib.sha256(rf_bytes).digest()
    result["rf"] = {"pairs": pairs, "bytes_hex": rf_bytes.hex(), "sha256": digest.hex()}
    result["mapping"] = map_digest(digest, req["tickets"], rules["mapping_max_words"])
    if result["mapping"]["index"] is None:
        result["reason"] = "MAPPING_EXHAUSTED"
    else:
        result["status"] = "DRAW"
    return result
