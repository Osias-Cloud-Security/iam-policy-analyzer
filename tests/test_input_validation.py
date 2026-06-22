"""P1: malformed input must be INVALID (stop and report), never a clean LOW."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from _engine import analyze, risk  # noqa: E402


def _identity(statement):
    return {"Version": "2012-10-17", "Statement": [statement]}


class TestDocumentLevelInvalid(unittest.TestCase):
    def test_bad_json_is_invalid(self):
        result = analyze("{not valid json")
        self.assertEqual(result["analysis_status"], "INVALID")
        self.assertIsNone(risk(result))
        self.assertFalse(result["valid"])

    def test_not_an_object_is_invalid(self):
        result = analyze("[1, 2, 3]")
        self.assertEqual(result["analysis_status"], "INVALID")
        self.assertIsNone(risk(result))

    def test_no_statement_is_invalid(self):
        result = analyze({"Version": "2012-10-17"})
        self.assertEqual(result["analysis_status"], "INVALID")
        self.assertIsNone(risk(result))

    def test_empty_statement_array_is_invalid(self):
        result = analyze({"Version": "2012-10-17", "Statement": []})
        self.assertEqual(result["analysis_status"], "INVALID")


class TestStatementLevelInvalid(unittest.TestCase):
    """A single malformed statement makes the WHOLE policy INVALID — AWS would
    reject it on submission, so the engine must not score a subset."""

    def assertInvalid(self, statement, idx=0, reason_contains=None):
        result = analyze(_identity(statement))
        self.assertEqual(result["analysis_status"], "INVALID")
        self.assertIsNone(risk(result), "INVALID must not carry a risk level")
        self.assertEqual(result["findings"], [])
        self.assertIn("invalid_statements", result)
        entry = next(e for e in result["invalid_statements"] if e["statement_index"] == idx)
        if reason_contains:
            self.assertIn(reason_contains, entry["reason"])
        return result

    def test_non_object_statement(self):
        result = analyze({"Version": "2012-10-17", "Statement": [42]})
        self.assertEqual(result["analysis_status"], "INVALID")
        self.assertIn("not a JSON object", result["invalid_statements"][0]["reason"])

    def test_missing_effect(self):
        # Regression: this previously read as a clean LOW even though it deletes
        # any object in the account.
        self.assertInvalid({"Action": "s3:DeleteObject", "Resource": "*"}, reason_contains="Effect")

    def test_invalid_effect_value(self):
        self.assertInvalid({"Effect": "Permit", "Action": "s3:GetObject", "Resource": "*"},
                           reason_contains="Effect")

    def test_missing_action_and_notaction(self):
        self.assertInvalid({"Effect": "Allow", "Resource": "*"}, reason_contains="Action")

    def test_missing_resource_and_notresource(self):
        self.assertInvalid({"Effect": "Allow", "Action": "s3:GetObject"}, reason_contains="Resource")

    def test_invalid_action_type(self):
        self.assertInvalid({"Effect": "Allow", "Action": 123, "Resource": "*"},
                           reason_contains="Action")

    def test_invalid_action_list_element_type(self):
        self.assertInvalid({"Effect": "Allow", "Action": ["s3:GetObject", 5], "Resource": "*"},
                           reason_contains="Action")

    def test_invalid_resource_type(self):
        self.assertInvalid({"Effect": "Allow", "Action": "s3:GetObject", "Resource": {"x": 1}},
                           reason_contains="Resource")

    def test_invalid_condition_type(self):
        self.assertInvalid({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
                            "Condition": "nope"}, reason_contains="Condition")

    def test_mixed_valid_and_invalid_is_whole_policy_invalid(self):
        result = analyze({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
            {"Action": "*", "Resource": "*"},  # missing Effect
        ]})
        self.assertEqual(result["analysis_status"], "INVALID")
        self.assertIsNone(risk(result))
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["invalid_statements"][0]["statement_index"], 1)


class TestValidInputsStayComplete(unittest.TestCase):
    def test_well_formed_policy_is_complete(self):
        result = analyze(_identity({"Effect": "Allow", "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::b/*"}))
        self.assertEqual(result["analysis_status"], "COMPLETE")

    def test_deny_only_policy_is_complete_not_invalid(self):
        # A Deny statement is valid and understood; it just grants nothing.
        result = analyze({"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "Action": "*", "Resource": "*"}]})
        self.assertEqual(result["analysis_status"], "COMPLETE")
        self.assertEqual(risk(result), "LOW")
        self.assertTrue(result["explicit_deny_present"])

    def test_no_invalid_policy_ever_reports_low(self):
        for statement in (42, {"Action": "s3:*", "Resource": "*"},
                          {"Effect": "Allow", "Resource": "*"}):
            result = analyze({"Version": "2012-10-17", "Statement": [statement]})
            self.assertNotEqual(risk(result), "LOW")


if __name__ == "__main__":
    unittest.main()
