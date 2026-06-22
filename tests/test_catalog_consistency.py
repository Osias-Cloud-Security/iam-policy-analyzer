"""Guards code <-> docs drift: every finding id the engine can emit must be
documented in reference/analysis.md. Catches a severity/id changing in the engine
but not the doc — the highest-stakes drift the prose Maintenance note can't.
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from _engine import ap  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "scripts", "analyze_policy.py")
DOC = os.path.join(os.path.dirname(__file__), "..", "reference", "analysis.md")


def _emitted_ids():
    """Literal finding ids passed to _make_finding() in the engine source."""
    return set(re.findall(r'_make_finding\(\s*"([A-Z_]+)"', open(SCRIPT, encoding="utf-8").read()))


class TestCatalogConsistency(unittest.TestCase):
    def setUp(self):
        self.doc = open(DOC, encoding="utf-8").read()

    def test_every_literal_finding_id_is_documented(self):
        for fid in sorted(_emitted_ids()):
            self.assertIn(fid, self.doc, f"{fid} is emitted but not in analysis.md")

    def test_service_wildcard_family_documented_and_categorized(self):
        self.assertIn("SERVICE_WILDCARD_", self.doc)
        for svc in ap.SENSITIVE_WILDCARD_SERVICES:
            self.assertEqual(ap._category_for(f"SERVICE_WILDCARD_{svc.upper()}", "HIGH"), "BROAD_PERMISSION")

    def test_no_finding_falls_through_to_review_required(self):
        for fid in _emitted_ids():
            self.assertNotEqual(ap._category_for(fid, "HIGH"), "REVIEW_REQUIRED",
                                f"{fid} has no explicit category mapping")


if __name__ == "__main__":
    unittest.main()
