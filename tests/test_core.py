"""Independent, synthetic-only checks for the v0.2 research contract.

The fixture builder, rational oracle and golden vectors do not call production
helpers. Passing these tests establishes arithmetic/replay behaviour only.
"""

from copy import deepcopy
from decimal import localcontext, ROUND_DOWN, ROUND_UP
from fractions import Fraction
import hashlib
import json
import struct
import unittest
from unittest.mock import patch

from meshdraw_core import core


GOLDEN_PAIRS = [[-400, 8], [-392, 12], [-396, 2], [-388, 16]]
GOLDEN_BYTES = (
    "4d657368447261772d636f72652d76302e322f44454455505f4841534800"
    "00000004fffffe7000000008fffffe780000000cfffffe7400000002fffffe7c00000010"
)
GOLDEN_RF = "8515a438e8f0bcaf633381eaf7f2341798987e54641acd0808601f81982188f3"
GOLDEN_SECOND_WORD = "48bcbfa64c6ef0e4fa7366d45091e58bb19b26b2dbecad8cf5604fb06f8a1fc5"
GOLDEN_CHANGED_RF = "363a59ee83e9fdd946c84afba58cf058377b069eddefaffea7ac0f62aaa56d73"
GOLDEN_TWO_RF = "fd5cdfe30c4d59baacd0de8a4b0948afc4dfa9e7e5cd0ce2eddb7298af53a993"


def independent_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def rational_quarter(text):
    """Round using floor intervals, unlike a sign/magnitude implementation."""
    value = Fraction(text) * 4
    lower = value.numerator // value.denominator
    distance = value - lower
    if distance < Fraction(1, 2):
        return lower
    if distance > Fraction(1, 2):
        return lower + 1
    return lower if lower % 2 == 0 else lower + 1


def make_request():
    """Six invented rows: four representatives, one ambiguity, one exclusion."""
    def row(rid, seq, observer, packet, source, received, rssi, snr, retained=False):
        return {
            "record_id": rid, "seq": seq, "observer_id": observer,
            "packet_id": packet, "event_type": "PACKET", "direction": "RX",
            "retained": retained, "source_time_us": source,
            "received_time_us": received, "rssi": rssi, "snr": snr,
        }

    return {
        "schema_version": "meshdraw-core-v0.2", "draw_id": "synthetic-test-001",
        "tickets": ["0007", "0042", "9001"],
        "rules": {
            "candidate": "DEDUP_HASH", "candidate_version": "core-v0.2",
            "canonicalization": "ascii-json-v0.2", "start_us": 1000000,
            "end_us": 2000000, "delivery_deadline_us": 2100000,
            "allowed_observers": ["rx-a", "rx-b"], "event_type": "PACKET",
            "direction": "RX", "retained_policy": "exclude",
            "rssi_min": "-200", "rssi_max": "10",
            "snr_min": "-50", "snr_max": "50",
            "quantization": "quarter-half-even",
            "dedup_policy": "observer-packet-earliest-source-received-seq",
            "ambiguity_policy": "retain-and-report", "min_rows": 4,
            "min_observers": 2, "mapping_max_words": 1024,
        },
        "source": {
            "dataset_id": "synthetic-only", "adapter_version": "synthetic-v1",
            "region": "SYNTHETIC", "rssi_unit": "dBm", "snr_unit": "dB",
            "time_unit": "utc-epoch-us", "provenance": "invented-no-capture",
            "limitations": ["no-entropy-claim", "no-completeness-proof"],
        },
        "observations": [
            row("r1", 10, "rx-b", "p2", 1010000, 1010001, "-99.125", "0.375"),
            row("r2", 20, "rx-a", "p1", 1000100, 1000101, "-100", "2"),
            row("r3", 30, "rx-b", "p1", 1000100, 1000102, "-98", "3"),
            row("r4", 40, "rx-a", "p2", 1020000, 1020001, "-97", "4"),
            row("r5", 50, "rx-a", "p1", 1000100, 1000103, "-101", "2"),
            row("r6", 60, "rx-a", "p3", 1030000, 1030001, "-90", "10", True),
        ],
    }


class CoreTests(unittest.TestCase):
    def assert_input_error(self, action, status="INVALID_INPUT", code=None):
        with self.assertRaises(core.InputError) as caught:
            action()
        self.assertEqual(caught.exception.status, status)
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_golden_four_representatives_and_sparse_ticket(self):
        result = core.evaluate(make_request())
        oracle = (b"MeshDraw-core-v0.2/DEDUP_HASH\0" + struct.pack(">I", 4)
                  + b"".join(struct.pack(">ii", *pair) for pair in GOLDEN_PAIRS))
        self.assertEqual(oracle.hex(), GOLDEN_BYTES)
        self.assertEqual(hashlib.sha256(oracle).hexdigest(), GOLDEN_RF)
        self.assertEqual(result["status"], "DRAW")
        self.assertEqual(result["rf"]["pairs"], GOLDEN_PAIRS)
        self.assertEqual(result["rf"]["bytes_hex"], GOLDEN_BYTES)
        self.assertEqual(result["rf"]["sha256"], GOLDEN_RF)
        self.assertEqual(result["mapping"], {"index": 1, "ticket": "0042", "words_used": 1})
        self.assertEqual(result["selection"]["selected_record_ids"], ["r2", "r3", "r1", "r4"])
        self.assertEqual(result["counts"], {
            "input_rows": 6, "accepted_rows": 5, "excluded_rows": 1,
            "accepted_observers": 2, "selected_rows": 4, "selected_observers": 2,
        })

    def test_second_golden_vector_changes_actual_winner(self):
        request = make_request()
        request["observations"][1]["rssi"] = "-101"
        result = core.evaluate(request)
        pairs = [[-404, 8], [-392, 12], [-396, 2], [-388, 16]]
        raw = b"MeshDraw-core-v0.2/DEDUP_HASH\0" + struct.pack(">I", 4)
        raw += b"".join(struct.pack(">ii", *pair) for pair in pairs)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), GOLDEN_CHANGED_RF)
        self.assertEqual(result["rf"]["sha256"], GOLDEN_CHANGED_RF)
        self.assertEqual(result["mapping"]["ticket"], "0007")

    def test_third_golden_two_rows(self):
        request = make_request()
        request["observations"] = request["observations"][1:3]
        request["rules"]["min_rows"] = 2
        result = core.evaluate(request)
        raw = b"MeshDraw-core-v0.2/DEDUP_HASH\0" + struct.pack(">Iiiii", 2, -400, 8, -392, 12)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), GOLDEN_TWO_RF)
        self.assertEqual(result["rf"]["sha256"], GOLDEN_TWO_RF)

    def test_canonical_json_and_hash_oracles(self):
        request = make_request()
        expected_input = hashlib.sha256(independent_json(request)).hexdigest()
        plan = {key: value for key, value in request.items() if key != "observations"}
        expected_plan = hashlib.sha256(independent_json(plan)).hexdigest()
        self.assertEqual(core.canonical_bytes({"b": [1, False], "a": None}),
                         b'{"a":null,"b":[1,false]}')
        self.assertEqual(core.input_hash(request), expected_input)
        self.assertEqual(core.plan_hash(request), expected_plan)
        self.assertEqual(core.evaluate(request)["input_sha256"], expected_input)
        reversed_keys = dict(reversed(list(request.items())))
        self.assertEqual(core.input_hash(reversed_keys), expected_input)

    def test_observation_permutation_preserves_rf_but_not_full_input_hash(self):
        request = make_request()
        shuffled = deepcopy(request)
        shuffled["observations"] = list(reversed(shuffled["observations"]))
        original, changed = core.evaluate(request), core.evaluate(shuffled)
        self.assertEqual(original["plan_sha256"], changed["plan_sha256"])
        self.assertNotEqual(original["input_sha256"], changed["input_sha256"])
        for key in ("rf", "mapping", "selection", "diagnostics", "counts"):
            self.assertEqual(original[key], changed[key], key)

    def test_still_excluded_metric_changes_only_input_hash(self):
        request = make_request()
        changed = deepcopy(request)
        changed["observations"][-1]["rssi"] = "-91.125"
        before, after = core.evaluate(request), core.evaluate(changed)
        self.assertNotEqual(before.pop("input_sha256"), after.pop("input_sha256"))
        self.assertEqual(before, after)

    def test_ambiguity_is_retained_reported_and_deduplicated(self):
        result = core.evaluate(make_request())
        self.assertEqual(result["status"], "DRAW")
        self.assertEqual(result["diagnostics"]["ambiguous_groups"], [{
            "observer_id": "rx-a", "packet_id": "p1", "source_time_us": 1000100,
            "record_ids": ["r2", "r5"],
        }])
        group = next(group for group in result["selection"]["representatives"]
                     if group["observer_id"] == "rx-a" and group["packet_id"] == "p1")
        self.assertEqual(group["selected_record_id"], "r2")
        self.assertEqual(group["record_ids"], ["r2", "r5"])

    def test_exact_rf_difference_before_quarter_is_an_ambiguity(self):
        request = make_request()
        request["observations"][4]["rssi"] = "-100.001"
        result = core.evaluate(request)
        self.assertEqual(len(result["diagnostics"]["ambiguous_groups"]), 1)
        self.assertEqual(result["rf"]["sha256"], GOLDEN_RF)
        request["observations"][4]["rssi"] = "-100.00"
        request["observations"][4]["snr"] = "2.000"
        self.assertEqual(core.evaluate(request)["diagnostics"]["ambiguous_groups"], [])

    def test_excluded_rf_does_not_create_accepted_ambiguity(self):
        request = make_request()
        request["observations"] = request["observations"][:4] + request["observations"][-1:]
        before = core.evaluate(request)
        excluded = request["observations"][-1]
        excluded.update(observer_id="rx-a", packet_id="p1", source_time_us=1000100)
        after = core.evaluate(request)
        self.assertEqual(after["status"], "DRAW")
        self.assertEqual(after["diagnostics"]["ambiguous_groups"], [])
        self.assertEqual(before["rf"], after["rf"])
        self.assertNotEqual(before.pop("input_sha256"), after.pop("input_sha256"))
        self.assertEqual(before, after)

    def test_structurally_invalid_excluded_row_still_invalidates_input(self):
        request = make_request()
        self.assertTrue(request["observations"][-1]["retained"])
        request["observations"][-1]["rssi"] = "NaN"
        self.assert_input_error(lambda: core.evaluate(request))

    def test_dedup_uses_source_then_received_then_sequence(self):
        for field, value in (("source_time_us", 1000099), ("received_time_us", 1000100), ("seq", 19)):
            with self.subTest(field=field):
                request = make_request()
                request["observations"][4][field] = value
                if field == "seq":
                    request["observations"][4]["received_time_us"] = 1000101
                result = core.evaluate(request)
                self.assertIn("r5", result["selection"]["selected_record_ids"])
                self.assertNotIn("r2", result["selection"]["selected_record_ids"])

    def test_ticket_order_is_committed_and_leading_zeroes_are_preserved(self):
        request = make_request()
        before = core.evaluate(request)
        request["tickets"] = ["0042", "9001", "0007"]
        after = core.evaluate(request)
        self.assertNotEqual(before["plan_sha256"], after["plan_sha256"])
        self.assertEqual(before["rf"], after["rf"])
        self.assertEqual(after["mapping"]["ticket"], "9001")

    def test_invalid_and_numerically_duplicate_tickets(self):
        cases = [[], ["7"], ["7", "7"], ["7", "0007"], [7, "8"],
                 [True, "8"], ["-1", "8"], ["1.0", "8"], ["７", "8"],
                 ["1" * 33, "8"]]
        for tickets in cases:
            with self.subTest(tickets=tickets):
                request = make_request()
                request["tickets"] = tickets
                self.assert_input_error(lambda: core.evaluate(request))

    def test_time_adapter_preserves_six_digits_without_float(self):
        for value, unit, expected in [
            ("1.000001", "s", 1000001), ("1000.001", "ms", 1000001),
            (1000001, "us", 1000001),
            ("-0.000001", "s", -1),
            ("1970-01-01T00:00:01.000001Z", "iso8601", 1000001),
            ("1970-01-01T03:00:01.000001+03:00", "iso8601", 1000001),
            ("1970-01-01T00:00:01.1234560Z", "iso8601", 1123456),
        ]:
            with self.subTest(value=value, unit=unit):
                self.assertEqual(core.to_utc_us(value, unit), expected)

    def test_time_adapter_rejects_nonintegral_microseconds(self):
        for value, unit in [("1.0000001", "s"), ("1.0001", "ms"),
                            ("1970-01-01T00:00:01.1234561Z", "iso8601")]:
            with self.subTest(value=value):
                self.assert_input_error(lambda: core.to_utc_us(value, unit), code="UNSUPPORTED_PRECISION")

    def test_time_adapter_rejects_naive_zones_float_and_invalid_units(self):
        for value, unit in [(1.5, "s"), (True, "s"), ("1e3", "s"), ("1000001.000", "us"),
                            ("1970-01-01T00:00:01.123456", "iso8601"),
                            ("1970-01-01T00:00:01.123456+24:00", "iso8601"),
                            ("1970-01-01T00:00:60Z", "iso8601"), ("1", "guess")]:
            with self.subTest(value=value, unit=unit):
                self.assert_input_error(lambda: core.to_utc_us(value, unit))

    def test_quarter_half_even_both_signs_with_independent_rational_oracle(self):
        constants = {"0.125": 0, "0.375": 2, "0.625": 2, "0.875": 4,
                     "-0.125": 0, "-0.375": -2, "-0.625": -2, "-0.875": -4,
                     "-99.125": -396, "-99.375": -398, "0": 0, "-0": 0}
        for text, expected in constants.items():
            with self.subTest(text=text):
                self.assertEqual(rational_quarter(text), expected)
                self.assertEqual(core.quarter(text), expected)

    def test_decimal_context_cannot_change_quarters_or_result(self):
        for precision, rounding in [(2, ROUND_DOWN), (3, ROUND_UP), (50, ROUND_DOWN)]:
            with self.subTest(precision=precision, rounding=rounding), localcontext() as context:
                context.prec, context.rounding = precision, rounding
                self.assertEqual(core.quarter("-99.125"), -396)
                self.assertEqual(core.quarter("0.375"), 2)
                self.assertEqual(core.evaluate(make_request())["rf"]["sha256"], GOLDEN_RF)

    def test_window_and_delivery_exact_boundaries(self):
        request = make_request()
        base = request["observations"][0]
        request["rules"]["min_rows"] = request["rules"]["min_observers"] = 1
        for source, received, accepted, reason in [
            (1000000, 2100000, True, None), (1999999, 2100000, True, None),
            (999999, 2100000, False, "OUTSIDE_WINDOW"),
            (2000000, 2100000, False, "OUTSIDE_WINDOW"),
            (1000000, 2100001, False, "LATE_DELIVERY"),
        ]:
            with self.subTest(source=source, received=received):
                row = deepcopy(base)
                row.update(source_time_us=source, received_time_us=received)
                request["observations"] = [row]
                result = core.evaluate(request)
                self.assertEqual(result["counts"]["accepted_rows"], int(accepted))
                if reason:
                    self.assertIn(reason, result["selection"]["excluded"][0]["reasons"])

    def test_invalid_windows_and_timestamp_types(self):
        for key, value in [("end_us", 1000000), ("delivery_deadline_us", 1999999),
                           ("start_us", True), ("end_us", 2 ** 63)]:
            with self.subTest(key=key):
                request = make_request()
                request["rules"][key] = value
                self.assert_input_error(lambda: core.evaluate(request))
        for value in [1.5, "1000000", True, 2 ** 63]:
            with self.subTest(value=value):
                request = make_request()
                request["observations"][0]["source_time_us"] = value
                self.assert_input_error(lambda: core.evaluate(request))

    def test_all_exclusion_reasons_are_stable_and_count_rows_once(self):
        request = make_request()
        request["observations"][-1].update(
            event_type="OTHER", direction="TX", observer_id="rx-other",
            source_time_us=2000000, received_time_us=2100001, rssi="-201")
        result = core.evaluate(request)
        self.assertEqual(result["selection"]["excluded"], [{
            "record_id": "r6", "seq": 60, "reasons": ["WRONG_EVENT", "RETAINED",
            "OBSERVER_NOT_ALLOWED", "OUTSIDE_WINDOW", "LATE_DELIVERY", "OUT_OF_RANGE"],
        }])
        self.assertEqual(result["counts"]["accepted_rows"] + result["counts"]["excluded_rows"], 6)

    def test_null_excludes_but_zero_is_a_value(self):
        request = make_request()
        request["observations"][0]["rssi"] = None
        request["rules"]["min_rows"] = 3
        result = core.evaluate(request)
        excluded = next(row for row in result["selection"]["excluded"] if row["record_id"] == "r1")
        self.assertIn("MISSING_FIELD", excluded["reasons"])
        request["observations"][0]["rssi"] = "0"
        request["observations"][0]["snr"] = "0"
        result = core.evaluate(request)
        self.assertIn([0, 0], result["rf"]["pairs"])

    def test_no_draw_before_dedup_has_no_rf_or_mapping(self):
        request = make_request()
        request["rules"]["min_rows"] = 6
        result = core.evaluate(request)
        self.assertEqual((result["status"], result["reason"]),
                         ("NO_DRAW", "INSUFFICIENT_ROWS_OR_OBSERVERS"))
        self.assertIsNone(result["rf"])
        self.assertIsNone(result["mapping"])
        self.assertIsNone(result["counts"]["selected_rows"])

    def test_no_draw_after_dedup_with_real_selected_counts(self):
        request = make_request()
        request["rules"]["min_rows"] = 5
        result = core.evaluate(request)
        self.assertEqual((result["status"], result["reason"]),
                         ("NO_DRAW", "INSUFFICIENT_DEDUP_ROWS_OR_OBSERVERS"))
        self.assertEqual(result["counts"]["accepted_rows"], 5)
        self.assertEqual(result["counts"]["selected_rows"], 4)
        self.assertEqual(result["counts"]["selected_observers"], 2)
        self.assertIsNone(result["rf"])
        self.assertIsNone(result["mapping"])

    def test_observer_minimum_and_all_excluded(self):
        request = make_request()
        request["rules"]["allowed_observers"] = ["rx-a"]
        self.assertEqual(core.evaluate(request)["reason"], "INSUFFICIENT_ROWS_OR_OBSERVERS")
        request = make_request()
        for row in request["observations"]:
            row["retained"] = True
        result = core.evaluate(request)
        self.assertEqual(result["counts"]["accepted_rows"], 0)
        self.assertEqual(result["status"], "NO_DRAW")

    def test_duplicate_local_keys_are_conflicts_even_with_same_rf(self):
        for key, code in [("record_id", "DUPLICATE_RECORD_ID"), ("seq", "DUPLICATE_SEQUENCE")]:
            with self.subTest(key=key):
                request = make_request()
                request["observations"][1][key] = request["observations"][0][key]
                self.assert_input_error(lambda: core.evaluate(request), "CONFLICTING_INPUT", code)

    def test_closed_schema_and_wrong_types(self):
        cases = [("schema_version", "meshdraw-core-v0.1"), ("draw_id", "bad id"),
                 ("observations", {}), ("tickets", "7,8"), ("source", None)]
        for key, value in cases:
            with self.subTest(key=key):
                request = make_request()
                request[key] = value
                self.assert_input_error(lambda: core.evaluate(request))
        for section in (None, "rules", "source"):
            with self.subTest(extra=section):
                request = make_request()
                (request if section is None else request[section])["typo"] = "synthetic"
                self.assert_input_error(lambda: core.evaluate(request))
        for key, value in [("seq", True), ("seq", -1), ("retained", 0),
                           ("rssi", 0), ("snr", "NaN"), ("rssi", "1e2")]:
            with self.subTest(row_key=key, value=value):
                request = make_request()
                request["observations"][0][key] = value
                self.assert_input_error(lambda: core.evaluate(request))

    def test_invalid_json_duplicate_keys_and_noninteger_numbers(self):
        for data in [b"", b"{", b'[]', b'null', b'{"x":1,"x":2}',
                     b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1.25}',
                     b'{"x":1e2}', b'{"x":"\xff"}', '{"x":"я"}'.encode("utf-8")]:
            with self.subTest(data=data):
                self.assert_input_error(lambda: core.load_request_json(data))
        self.assert_input_error(lambda: core.load_request_json(b'{"x":1,"x":2}'),
                                code="DUPLICATE_JSON_KEY")

    def test_resource_limits_bytes_rows_numeric_length_and_depth(self):
        self.assert_input_error(lambda: core.load_request_json(b" " * (2 * 1024 * 1024 + 1)))
        self.assert_input_error(lambda: core.load_request_json(b'{"x":' + b"9" * 100 + b'}'))
        self.assert_input_error(lambda: core.load_request_json(b'{"x":' + b"[" * 40 + b"0" + b"]" * 40 + b'}'))
        request = make_request()
        request["observations"] = request["observations"][:1] * 10001
        self.assert_input_error(lambda: core.evaluate(request))
        request = make_request()
        request["observations"][0]["rssi"] = "0." + "1" * 31
        self.assert_input_error(lambda: core.evaluate(request))
        request["observations"][0]["rssi"] = "0." + "1" * 30
        self.assertEqual(core.evaluate(request)["status"], "DRAW")
        request = make_request()
        request["draw_id"] = "a" * (2 * 1024 * 1024)
        self.assert_input_error(lambda: core.evaluate(request))

    def test_direct_objects_cannot_bypass_depth_cycle_or_node_limits(self):
        deep = value = {}
        for _ in range(40):
            value["child"] = {}
            value = value["child"]
        self.assert_input_error(lambda: core.validate_request(deep))
        cyclic = {}
        cyclic["cycle"] = cyclic
        self.assert_input_error(lambda: core.validate_request(cyclic))
        self.assert_input_error(lambda: core.validate_request({"nodes": [0] * 200001}))

    def test_source_units_and_unsupported_candidates_are_not_guessed(self):
        for section, key, value in [("source", "time_unit", "utc-epoch-ms"),
                                    ("source", "rssi_unit", "raw"),
                                    ("source", "snr_unit", "quarter-dB"),
                                    ("rules", "candidate", "RAW_HASH"),
                                    ("rules", "candidate", "GRID_MEDIAN"),
                                    ("rules", "ambiguity_policy", "reject")]:
            with self.subTest(section=section, key=key, value=value):
                request = make_request()
                request[section][key] = value
                self.assert_input_error(lambda: core.evaluate(request))

    def test_mapping_word_golden_and_independent_prefix_oracle(self):
        root = bytes.fromhex(GOLDEN_RF)
        oracle = hashlib.sha256(b"MeshDraw-core-map-v0.2\0" + root + struct.pack(">I", 1)).hexdigest()
        self.assertEqual(oracle, GOLDEN_SECOND_WORD)
        self.assertEqual(core._mapping_word(root, 0), root)
        self.assertEqual(core._mapping_word(root, 1).hex(), GOLDEN_SECOND_WORD)

    def test_mapping_rejection_limit_and_exhaustion(self):
        tickets = ["0007", "0042", "9001"]
        limit = ((1 << 256) // 3) * 3
        self.assertEqual(core.map_digest((limit - 1).to_bytes(32, "big"), tickets, 1),
                         {"index": 2, "ticket": "9001", "words_used": 1})
        with patch.object(core, "_mapping_word", side_effect=[limit.to_bytes(32, "big"), (0).to_bytes(32, "big")]):
            self.assertEqual(core.map_digest(bytes(32), tickets, 2),
                             {"index": 0, "ticket": "0007", "words_used": 2})
        with patch.object(core, "_mapping_word", return_value=limit.to_bytes(32, "big")):
            self.assertEqual(core.map_digest(bytes(32), tickets, 2),
                             {"index": None, "ticket": None, "words_used": 2})

    def test_mapping_power_of_two_accepts_maximum_word(self):
        maximum = ((1 << 256) - 1).to_bytes(32, "big")
        self.assertEqual(core.map_digest(maximum, ["0007", "0042"], 1),
                         {"index": 1, "ticket": "0042", "words_used": 1})

    def test_mapping_exhaustion_is_no_draw_and_keeps_computed_rf(self):
        request = make_request()
        request["rules"]["mapping_max_words"] = 2
        with patch.object(core, "_mapping_word", return_value=b"\xff" * 32):
            result = core.evaluate(request)
        self.assertEqual((result["status"], result["reason"]), ("NO_DRAW", "MAPPING_EXHAUSTED"))
        self.assertEqual(result["rf"]["sha256"], GOLDEN_RF)
        self.assertEqual(result["mapping"], {"index": None, "ticket": None, "words_used": 2})


if __name__ == "__main__":
    unittest.main()
