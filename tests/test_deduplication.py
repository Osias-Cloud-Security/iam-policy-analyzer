"""P6: FULL_ADMIN consolidation and finding dedup — exact-output regression."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from _engine import analyze, ids, by_id  # noqa: E402

SENSITIVE_SERVICES = sorted([
    "cloudformation", "ec2", "iam", "kms", "lambda",
    "organizations", "s3", "secretsmanager", "ssm", "sts",
])


def identity(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*"):
    return {"Effect": "Allow", "Action": action, "Resource": resource}


class TestFullAdminConsolidation(unittest.TestCase):
    def test_full_admin_yields_single_finding(self):
        result = analyze(identity(allow("*", "*")))
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["id"], "FULL_ADMIN")

    def test_affected_services_folded_into_metadata(self):
        result = analyze(identity(allow("*", "*")))
        meta = result["findings"][0]["metadata"]
        self.assertEqual(meta["affected_services"], SENSITIVE_SERVICES)

    def test_breadth_children_are_dropped(self):
        result = analyze(identity(allow("*", "*")))
        for dropped in ("SERVICE_WILDCARD_S3", "BROAD_S3_DATA_ACCESS",
                        "WILDCARD_ACTIONS_AND_RESOURCES", "WRITE_ON_ALL_RESOURCES"):
            self.assertNotIn(dropped, ids(result))

    def test_other_statement_keeps_its_service_wildcard(self):
        # Consolidation is statement-scoped: a different statement's breadth
        # finding must survive.
        result = analyze(identity(
            allow("*", "*"),
            allow("s3:*", "arn:aws:s3:::bucket/*"),
        ))
        wildcard = by_id(result, "SERVICE_WILDCARD_S3")
        self.assertIsNotNone(wildcard)
        self.assertEqual(wildcard["statement_index"], 1)
        self.assertIsNotNone(by_id(result, "FULL_ADMIN"))


class TestDedup(unittest.TestCase):
    def test_no_duplicate_id_per_statement(self):
        result = analyze(identity(allow(["secretsmanager:GetSecretValue", "kms:Decrypt"], "*")))
        sensitive = [f for f in result["findings"] if f["id"] == "SENSITIVE_DATA_ACCESS"]
        self.assertEqual(len(sensitive), 1)


if __name__ == "__main__":
    unittest.main()
