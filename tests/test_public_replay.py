"""Offline checks using the browser's synthetic vectors."""
from copy import deepcopy
from pathlib import Path
import unittest

from meshdraw_core.core import map_digest
from meshdraw_public.archive.math import digest, read
from meshdraw_public.verifier import verify_package


ROOT = Path(__file__).resolve().parents[1]
VECTORS = read(ROOT / "tests/fixtures/synthetic/browser-vectors.json")
PACKAGE = read(ROOT / "docs/verification.json")


class PublicReplayTests(unittest.TestCase):
    def test_common_packages(self):
        self.assertEqual(VECTORS["mode"], "SYNTHETIC")
        self.assertEqual(len(VECTORS["vectors"]), 8)
        for vector in VECTORS["vectors"]:
            with self.subTest(name=vector["name"]):
                package = vector["package"]
                self.assertEqual(package["mode"], "SYNTHETIC")
                replay = verify_package(package)
                self.assertEqual(replay["status"], "MATCH")
                self.assertEqual(replay["provenance"], "NOT_INDEPENDENTLY_CONFIRMED")
                self.assertEqual(replay["selection"], package["expected"]["selection"])
                self.assertEqual(replay["calculation"], package["expected"]["calculation"])

    def test_common_mapping(self):
        self.assertEqual(len(VECTORS["mapping_vectors"]), 4)
        for vector in VECTORS["mapping_vectors"]:
            with self.subTest(name=vector["name"]):
                value = map_digest(bytes.fromhex(vector["root_hex"]), vector["tickets"], vector["max_words"])
                self.assertEqual(value, vector["expected"])

    def test_demo_binding_and_repeat(self):
        state = read(ROOT / "docs/result.json")["state"]
        self.assertIs(state["synthetic"], True)
        self.assertEqual(PACKAGE["mode"], "SYNTHETIC")
        self.assertEqual(PACKAGE["policy"]["tickets"], state["tickets"])
        self.assertEqual(PACKAGE["projection"]["original_plan_sha256"], state["plan_sha256"])
        self.assertEqual(digest(PACKAGE), state["verification_sha256"])
        first = verify_package(PACKAGE)
        self.assertEqual(first, verify_package(PACKAGE))
        self.assertEqual(first["calculation"]["mapping"]["ticket"], state["winner"])
        self.assertEqual(state["winner"], "0002")

    def test_expected_changes_with_updated_manifest_are_rejected(self):
        for key, value in (("mapping", {"ticket": "0001"}), ("frozen_input_hash_match", 1)):
            with self.subTest(field=key):
                changed = deepcopy(PACKAGE)
                changed["expected"]["calculation"][key] = value
                changed["manifest"]["expected"] = digest(changed["expected"])
                with self.assertRaisesRegex(ValueError, "PUBLIC_REPLAY_MISMATCH"):
                    verify_package(changed)

    def test_incomplete_and_extra_fields_are_rejected(self):
        missing = deepcopy(PACKAGE)
        missing["snapshot"]["rows"].pop()
        with self.assertRaises(ValueError):
            verify_package(missing)
        changed = deepcopy(PACKAGE)
        changed["snapshot"]["rows"][0]["fields"]["observer_iata"] = {"kind": "string", "value": "example"}
        changed["manifest"]["snapshot"] = digest(changed["snapshot"])
        with self.assertRaisesRegex(ValueError, "UNSAFE_PUBLIC_FIELDS"):
            verify_package(changed)
        with self.assertRaisesRegex(ValueError, "PUBLIC_PACKAGE_FIELDS"):
            verify_package(dict(PACKAGE, participant_id="example"))
