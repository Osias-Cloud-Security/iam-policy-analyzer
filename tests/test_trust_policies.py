"""Trust-policy findings — driven by Principal and its Condition scoping."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from _engine import analyze, ids, by_id, risk  # noqa: E402

OIDC = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
SAML = "arn:aws:iam::111122223333:saml-provider/Okta"


def trust(statement):
    return {"Version": "2012-10-17", "Statement": [statement]}


def assume(principal, **extra):
    stmt = {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
    stmt.update(extra)
    return stmt


class TestClassification(unittest.TestCase):
    def test_trust_policy_detected(self):
        result = analyze(trust(assume({"AWS": "arn:aws:iam::111122223333:role/app"})))
        self.assertEqual(result["policy_type"], "trust")


class TestWildcardPrincipal(unittest.TestCase):
    def test_wildcard_no_condition_is_critical(self):
        result = analyze(trust(assume("*")))
        self.assertEqual(risk(result), "CRITICAL")
        self.assertEqual(by_id(result, "TRUST_PRINCIPAL_WILDCARD")["severity"], "CRITICAL")

    def test_wildcard_with_org_condition_is_high(self):
        result = analyze(trust(assume("*", Condition={
            "StringEquals": {"aws:PrincipalOrgID": "o-abc123"}})))
        self.assertEqual(by_id(result, "TRUST_PRINCIPAL_WILDCARD")["severity"], "HIGH")

    def test_wildcard_with_precise_arn_is_medium(self):
        result = analyze(trust(assume("*", Condition={
            "ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/app"}})))
        self.assertEqual(by_id(result, "TRUST_PRINCIPAL_WILDCARD")["severity"], "MEDIUM")


class TestAccountRoot(unittest.TestCase):
    def test_account_root_no_guard(self):
        result = analyze(trust(assume({"AWS": "arn:aws:iam::111122223333:root"})))
        self.assertIn("TRUST_ACCOUNT_ROOT", ids(result))
        self.assertIn("TRUST_CROSS_ACCOUNT_NO_EXTERNALID", ids(result))

    def test_account_root_with_externalid_no_cd_finding(self):
        result = analyze(trust(assume({"AWS": "arn:aws:iam::111122223333:root"}, Condition={
            "StringEquals": {"sts:ExternalId": "shared-secret-123"}})))
        self.assertNotIn("TRUST_CROSS_ACCOUNT_NO_EXTERNALID", ids(result))

    def test_specific_role_principal_is_clean(self):
        result = analyze(trust(assume({"AWS": "arn:aws:iam::111122223333:role/app"})))
        self.assertEqual(risk(result), "LOW")
        self.assertEqual(result["findings"], [])


class TestServicePrincipal(unittest.TestCase):
    def test_service_principal_is_clean(self):
        result = analyze(trust(assume({"Service": "ec2.amazonaws.com"})))
        self.assertEqual(risk(result), "LOW")
        self.assertEqual(result["findings"], [])


class TestFederation(unittest.TestCase):
    def _oidc(self, condition=None):
        stmt = {"Effect": "Allow", "Principal": {"Federated": OIDC},
                "Action": "sts:AssumeRoleWithWebIdentity"}
        if condition is not None:
            stmt["Condition"] = condition
        return trust(stmt)

    def test_oidc_without_condition_flagged(self):
        result = analyze(self._oidc())
        self.assertIn("TRUST_FEDERATED_UNSCOPED", ids(result))

    def test_oidc_wildcard_subject_flagged(self):
        # Regression (P9): a bare-wildcard :sub previously read as clean LOW.
        result = analyze(self._oidc({"StringLike": {
            "token.actions.githubusercontent.com:sub": "*"}}))
        self.assertIn("TRUST_FEDERATED_UNSCOPED", ids(result))

    def test_oidc_repo_branch_wildcard_is_clean(self):
        result = analyze(self._oidc({"StringLike": {
            "token.actions.githubusercontent.com:sub": "repo:acme/app:ref:refs/heads/*"}}))
        self.assertEqual(result["findings"], [])
        self.assertEqual(risk(result), "LOW")

    def test_saml_without_aud_flagged(self):
        result = analyze(trust({"Effect": "Allow", "Principal": {"Federated": SAML},
                                "Action": "sts:AssumeRoleWithSAML"}))
        self.assertIn("TRUST_SAML_UNSCOPED", ids(result))


class TestNotPrincipal(unittest.TestCase):
    def test_notprincipal_no_scope_is_critical(self):
        result = analyze(trust({"Effect": "Allow",
                                "NotPrincipal": {"AWS": "arn:aws:iam::111122223333:role/admin"},
                                "Action": "sts:AssumeRole"}))
        self.assertEqual(by_id(result, "TRUST_NOTPRINCIPAL")["severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
