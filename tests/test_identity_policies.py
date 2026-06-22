"""Identity-policy findings: positive, negative, scoped, and wildcard cases."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from _engine import analyze, ids, by_id, risk  # noqa: E402


def identity(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*", **extra):
    stmt = {"Effect": "Allow", "Action": action, "Resource": resource}
    stmt.update(extra)
    return stmt


class TestFullAdmin(unittest.TestCase):
    def test_full_admin_is_critical(self):
        result = analyze(identity(allow("*", "*")))
        self.assertEqual(risk(result), "CRITICAL")
        self.assertIsNotNone(by_id(result, "FULL_ADMIN"))

    def test_full_admin_category(self):
        result = analyze(identity(allow("*", "*")))
        self.assertEqual(by_id(result, "FULL_ADMIN")["category"], "SECURITY_RISK")


class TestServiceWildcard(unittest.TestCase):
    def test_iam_wildcard_scoped_resource(self):
        result = analyze(identity(allow("iam:*", "arn:aws:iam::111122223333:role/x")))
        self.assertIsNotNone(by_id(result, "SERVICE_WILDCARD_IAM"))
        self.assertIsNone(by_id(result, "FULL_ADMIN"))

    def test_service_wildcard_category(self):
        result = analyze(identity(allow("kms:*", "arn:aws:kms:us-east-1:111122223333:key/x")))
        self.assertEqual(by_id(result, "SERVICE_WILDCARD_KMS")["category"], "BROAD_PERMISSION")


class TestPassRole(unittest.TestCase):
    def test_passrole_wildcard_is_critical(self):
        result = analyze(identity(allow("iam:PassRole", "*")))
        self.assertEqual(by_id(result, "IAM_PASSROLE")["severity"], "CRITICAL")

    def test_passrole_scoped_is_high(self):
        result = analyze(identity(allow("iam:PassRole", "arn:aws:iam::111122223333:role/app")))
        self.assertEqual(by_id(result, "IAM_PASSROLE")["severity"], "HIGH")

    def test_passrole_category_is_escalation(self):
        result = analyze(identity(allow("iam:PassRole", "arn:aws:iam::111122223333:role/app")))
        self.assertEqual(by_id(result, "IAM_PASSROLE")["category"], "PRIVILEGE_ESCALATION")


class TestSensitiveDataAccess(unittest.TestCase):
    def test_scoped_secret_read_is_capability_not_defect(self):
        result = analyze(identity(allow(
            "secretsmanager:GetSecretValue",
            "arn:aws:secretsmanager:us-east-1:111122223333:secret:db-*")))
        finding = by_id(result, "SENSITIVE_DATA_ACCESS")
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["category"], "SENSITIVE_CAPABILITY")

    def test_wildcard_secret_read_is_high(self):
        result = analyze(identity(allow("kms:Decrypt", "*")))
        self.assertEqual(by_id(result, "SENSITIVE_DATA_ACCESS")["severity"], "HIGH")


class TestAssumeRoleTitle(unittest.TestCase):
    def test_scoped_assume_role_title_not_broad(self):
        result = analyze(identity(allow("sts:AssumeRole", "arn:aws:iam::111122223333:role/x")))
        finding = by_id(result, "STS_ASSUME_ROLE")
        self.assertNotIn("Broad", finding["title"])
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["category"], "SENSITIVE_CAPABILITY")

    def test_wildcard_assume_role_is_escalation(self):
        result = analyze(identity(allow("sts:AssumeRole", "*")))
        finding = by_id(result, "STS_ASSUME_ROLE")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["category"], "PRIVILEGE_ESCALATION")


class TestSensitiveDataPlaneReads(unittest.TestCase):
    def test_dynamodb_getitem_on_star_flagged(self):
        result = analyze(identity(allow("dynamodb:GetItem", "*")))
        self.assertEqual(by_id(result, "SENSITIVE_DATA_ACCESS")["severity"], "HIGH")

    def test_dynamodb_scan_on_star_flagged(self):
        result = analyze(identity(allow("dynamodb:Scan", "*")))
        self.assertIsNotNone(by_id(result, "SENSITIVE_DATA_ACCESS"))

    def test_lambda_getfunction_on_star_flagged(self):
        result = analyze(identity(allow("lambda:GetFunction", "*")))
        self.assertIsNotNone(by_id(result, "SENSITIVE_DATA_ACCESS"))

    def test_scoped_dynamodb_getitem_is_clean(self):
        result = analyze(identity(allow("dynamodb:GetItem",
                                        "arn:aws:dynamodb:us-east-1:111122223333:table/Orders")))
        self.assertEqual(result["findings"], [])

    def test_metadata_read_on_star_stays_clean(self):
        result = analyze(identity(allow("ec2:DescribeInstances", "*")))
        self.assertEqual(risk(result), "LOW")


class TestWriteAndWildcards(unittest.TestCase):
    def test_write_on_all_resources(self):
        result = analyze(identity(allow("ec2:TerminateInstances", "*")))
        self.assertIn("WRITE_ON_ALL_RESOURCES", ids(result))

    def test_notaction_flagged(self):
        result = analyze(identity({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
        self.assertIn("ALLOW_NOTACTION", ids(result))

    def test_notresource_flagged(self):
        result = analyze(identity({"Effect": "Allow", "Action": "s3:PutObject",
                                   "NotResource": "arn:aws:s3:::safe/*"}))
        self.assertIn("ALLOW_NOTRESOURCE", ids(result))


class TestNegativeReadOnly(unittest.TestCase):
    def test_readonly_audit_role_is_low(self):
        result = analyze(identity(
            allow(["ec2:DescribeInstances", "iam:ListRoles", "s3:ListAllMyBuckets",
                   "cloudwatch:GetMetricData"], "*")))
        self.assertEqual(risk(result), "LOW")
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
