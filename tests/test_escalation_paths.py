"""Privilege-escalation findings: PassRole + compute, policy mutation, chains."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from _engine import analyze, ids, by_id  # noqa: E402


def identity(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*"):
    return {"Effect": "Allow", "Action": action, "Resource": resource}


class TestComputeRoleInjection(unittest.TestCase):
    def test_passrole_plus_lambda_same_statement(self):
        result = analyze(identity(allow(["iam:PassRole", "lambda:CreateFunction"], "*")))
        finding = by_id(result, "COMPUTE_ROLE_INJECTION")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["statement_index"], 0)

    def test_passrole_plus_compute_across_statements(self):
        result = analyze(identity(
            allow("iam:PassRole", "arn:aws:iam::111122223333:role/app"),
            allow("ec2:RunInstances", "*"),
        ))
        finding = by_id(result, "COMPUTE_ROLE_INJECTION")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["statement_index"], -1)  # cross-statement

    def test_compute_without_passrole_is_compute_control(self):
        result = analyze(identity(allow("lambda:CreateFunction", "*")))
        self.assertIn("COMPUTE_CONTROL", ids(result))
        self.assertIsNone(by_id(result, "COMPUTE_ROLE_INJECTION"))

    def test_scoped_compute_control_title_not_broad(self):
        result = analyze(identity(allow("glue:CreateJob",
                                        "arn:aws:glue:us-east-1:111122223333:job/x")))
        finding = by_id(result, "COMPUTE_CONTROL")
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertNotIn("Broad", finding["title"])


class TestPolicyMutation(unittest.TestCase):
    def test_attach_role_policy_is_high(self):
        result = analyze(identity(allow("iam:AttachRolePolicy",
                                        "arn:aws:iam::111122223333:role/app")))
        self.assertEqual(by_id(result, "IAM_POLICY_MUTATION")["severity"], "HIGH")

    def test_create_policy_version_is_critical(self):
        result = analyze(identity(allow("iam:CreatePolicyVersion",
                                        "arn:aws:iam::111122223333:policy/p")))
        self.assertEqual(by_id(result, "IAM_POLICY_MUTATION")["severity"], "CRITICAL")

    def test_mutation_category_is_escalation(self):
        result = analyze(identity(allow("iam:PutRolePolicy", "*")))
        self.assertEqual(by_id(result, "IAM_POLICY_MUTATION")["category"], "PRIVILEGE_ESCALATION")


class TestCredentialEscalation(unittest.TestCase):
    def test_create_access_key_wildcard_is_high(self):
        result = analyze(identity(allow("iam:CreateAccessKey", "*")))
        finding = by_id(result, "CREDENTIAL_ESCALATION")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["category"], "PRIVILEGE_ESCALATION")

    def test_update_assume_role_policy_scoped_is_medium(self):
        result = analyze(identity(allow("iam:UpdateAssumeRolePolicy",
                                        "arn:aws:iam::111122223333:role/app")))
        self.assertEqual(by_id(result, "CREDENTIAL_ESCALATION")["severity"], "MEDIUM")

    def test_add_user_to_group_flagged(self):
        result = analyze(identity(allow("iam:AddUserToGroup", "*")))
        self.assertIn("CREDENTIAL_ESCALATION", ids(result))

    def test_non_credential_action_not_flagged(self):
        result = analyze(identity(allow("iam:GetUser", "*")))
        self.assertIsNone(by_id(result, "CREDENTIAL_ESCALATION"))


class TestNegative(unittest.TestCase):
    def test_passrole_alone_no_injection(self):
        result = analyze(identity(allow("iam:PassRole", "arn:aws:iam::111122223333:role/app")))
        self.assertIsNone(by_id(result, "COMPUTE_ROLE_INJECTION"))
        self.assertIsNotNone(by_id(result, "IAM_PASSROLE"))


if __name__ == "__main__":
    unittest.main()
