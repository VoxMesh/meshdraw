"""Sufficient public projection for archive-input-v1 mathematical replay.

The projection preserves RF numbers, times, grouping and ordering, while replacing
technical identifiers with ordered aliases. Its hashes describe the projection,
not the original snapshot. No independent source provenance is established.
"""
import re

from meshdraw_core.core import canonical_bytes, to_utc_us
from .archive import math as archive_math, profile
from .archive.math import digest


SCHEMA = "meshdraw-public-verification-v1"
PROJECTION_POLICY = "order-preserving-identifiers-v1"
PROVENANCE = "NOT_INDEPENDENTLY_CONFIRMED"
TOP_FIELDS = {"schema_version", "mode", "algorithm_version", "projection", "policy",
              "snapshot", "expected", "manifest"}
PROJECTION_FIELDS = {"policy", "provenance", "original_snapshot_sha256",
                     "original_plan_sha256", "original_rf_sha256"}
POLICY_FIELDS = {
    "profile", "candidate", "direction", "region", "grouping", "representative",
    "pair_order", "quantization", "rf_abs_limit", "min_rows", "min_observers",
    "mapping_max_words", "source_snapshot_sha256", "input_document_sha256_before_calculation",
    "start", "end", "tickets", "physical_source_time", "physical_receive_time",
    "retained", "rf_prefix_hex", "mapping",
}
PACKET_FIELDS = {"id", "first_seen", "observation_count"}
CHILD_FIELDS = {"id", "observer_id", "timestamp", "direction", "rssi", "snr"}


def _typed(kind, value):
    return {"kind": kind, "value": value}


def _input(policy, snapshot):
    plan = {"source": {"query": {"since": policy["start"], "until": policy["end"]}}}
    children, selection = profile.window_filter(plan, snapshot)
    return {"schema_version": "meshdraw-archive-input-v1", "source_snapshot_sha256": digest(snapshot),
            "archive_timestamp_meaning": "Published archive field, physical times unknown",
            "download_time_meaning": "request_utc is extraction metadata, never RF input",
            "retained": "unknown-not-provided", "rows": children}, selection


def _validate_alias(field, prefix):
    if (field["kind"] == "integer" and re.fullmatch(r"1[0-9]{6}", field["value"])
            or field["kind"] == "string" and re.fullmatch(prefix + r"-[0-9]{6}", field["value"])):
        return
    raise ValueError("UNSAFE_PUBLIC_IDENTIFIER")


def verify_package(package):
    """Replay every mathematical step from the public snapshot, with no network."""
    profile.exact_fields(package, TOP_FIELDS, "PUBLIC_PACKAGE_FIELDS")
    if (package["schema_version"] != SCHEMA or package["mode"] not in ("SYNTHETIC", "REVIEWED_PROJECTION")
            or package["algorithm_version"] != archive_math.IMPLEMENTATION_VERSION):
        raise ValueError("UNSUPPORTED_PUBLIC_PACKAGE")
    # ASCII canonicalisation provides the same bounded hash domain as Python math.
    canonical_bytes(package)
    projection = package["projection"]
    profile.exact_fields(projection, PROJECTION_FIELDS, "PUBLIC_PROJECTION_FIELDS")
    if projection["policy"] != PROJECTION_POLICY or projection["provenance"] != PROVENANCE:
        raise ValueError("UNSUPPORTED_PUBLIC_PROJECTION")
    for key in ("original_snapshot_sha256", "original_plan_sha256", "original_rf_sha256"):
        value = projection[key]
        if key == "original_rf_sha256" and value is None:
            continue
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("PUBLIC_COMMITMENT_HASH")
    policy, snapshot = package["policy"], package["snapshot"]
    profile.exact_fields(policy, POLICY_FIELDS, "PUBLIC_POLICY_FIELDS")
    archive_math.validate_policy(policy)
    profile.check_snapshot(snapshot, 3000, 100)
    for row in snapshot["rows"]:
        fields = row["fields"]
        if set(fields) - (PACKET_FIELDS if row["layer"] == "packet" else CHILD_FIELDS):
            raise ValueError("UNSAFE_PUBLIC_FIELDS")
        _validate_alias(fields["id"], "parent" if row["layer"] == "packet" else "observation")
        observer = fields.get("observer_id")
        if observer and observer["kind"] in ("string", "integer") and observer["value"] != "":
            _validate_alias(observer, "observer")
        elif observer and observer != _typed("null", None):
            raise ValueError("UNSAFE_PUBLIC_IDENTIFIER")
        for key in ("first_seen", "timestamp"):
            if key in fields and fields[key]["value"] != "invalid-archive-time":
                to_utc_us(fields[key]["value"], "iso8601")
        if "direction" in fields and fields["direction"] not in (_typed("string", "rx"), _typed("string", "not-rx")):
            raise ValueError("UNSAFE_PUBLIC_DIRECTION")
        to_utc_us(row["request_utc"], "iso8601")
    expected = package["expected"]
    profile.exact_fields(expected, {"selection", "calculation"}, "PUBLIC_EXPECTED_FIELDS")
    profile.exact_fields(package["manifest"], {"policy", "snapshot", "expected", "projection"}, "PUBLIC_MANIFEST_FIELDS")
    if any(package["manifest"][key] != digest(package[key]) for key in package["manifest"]):
        raise ValueError("PUBLIC_PACKAGE_HASH_MISMATCH")
    inp, selection = _input(policy, snapshot)
    if digest(snapshot) != policy["source_snapshot_sha256"] or digest(inp) != policy["input_document_sha256_before_calculation"]:
        raise ValueError("PUBLIC_INPUT_HASH_MISMATCH")
    calculation = archive_math.evaluate(policy, inp)
    if canonical_bytes(expected) != canonical_bytes({"selection": selection, "calculation": calculation}):
        raise ValueError("PUBLIC_REPLAY_MISMATCH")
    rf_hash = calculation["rf"]["sha256"] if calculation["rf"] else None
    if rf_hash != projection["original_rf_sha256"]:
        raise ValueError("PUBLIC_RF_COMMITMENT_MISMATCH")
    return {"status": "MATCH", "provenance": PROVENANCE, "selection": selection, "calculation": calculation}
