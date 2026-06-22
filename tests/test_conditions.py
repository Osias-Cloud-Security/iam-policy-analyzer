"""Effective-condition inspection: only a real, narrowing condition counts."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from _engine import ap  # noqa: E402  (ap = the analyze_policy module)


def stmt(condition):
    return {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole",
            "Condition": condition}


class TestEffectiveConditions(unittest.TestCase):
    def test_real_value_narrows_to_precise(self):
        s = stmt({"ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/app"}})
        self.assertEqual(ap._scope_tier(s), "precise")

    def test_broad_key_is_broad(self):
        s = stmt({"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}})
        self.assertEqual(ap._scope_tier(s), "broad")

    def test_ifexists_does_not_narrow(self):
        s = stmt({"StringEqualsIfExists": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/app"}})
        self.assertEqual(ap._scope_tier(s), "none")

    def test_negative_operator_does_not_narrow(self):
        s = stmt({"StringNotEquals": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/app"}})
        self.assertEqual(ap._scope_tier(s), "none")

    def test_forallvalues_does_not_narrow(self):
        s = stmt({"ForAllValues:StringEquals": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/app"}})
        self.assertEqual(ap._scope_tier(s), "none")

    def test_wildcard_value_does_not_narrow(self):
        s = stmt({"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/*"}})
        self.assertEqual(ap._scope_tier(s), "none")

    def test_account_root_arn_value_is_broad_not_precise(self):
        s = stmt({"ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::111122223333:root"}})
        self.assertEqual(ap._scope_tier(s), "broad")


class TestReadOnlyHelper(unittest.TestCase):
    def test_star_is_not_read_only(self):
        # Regression: `*` must not be treated as all-read-only (vacuous all()).
        self.assertFalse(ap._all_actions_read_only(["*"]))

    def test_empty_is_not_read_only(self):
        self.assertFalse(ap._all_actions_read_only([]))

    def test_describe_get_list_are_read_only(self):
        self.assertTrue(ap._all_actions_read_only(["ec2:describeinstances", "s3:listbucket"]))

    def test_mixed_write_is_not_read_only(self):
        self.assertFalse(ap._all_actions_read_only(["s3:getobject", "s3:putobject"]))


if __name__ == "__main__":
    unittest.main()
