"""S3 object-data classification — preserve the corrected behavior."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from _engine import analyze, ids, by_id, risk  # noqa: E402


def identity(action, resource="*"):
    return {"Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}]}


class TestS3DataAccess(unittest.TestCase):
    def test_list_all_my_buckets_is_not_object_data(self):
        result = analyze(identity("s3:ListAllMyBuckets", "*"))
        self.assertIsNone(by_id(result, "BROAD_S3_DATA_ACCESS"))

    def test_get_glob_on_star_covers_get_object(self):
        result = analyze(identity("s3:Get*", "*"))
        self.assertIsNotNone(by_id(result, "BROAD_S3_DATA_ACCESS"))
        self.assertEqual(risk(result), "HIGH")

    def test_service_wildcard_covers_object_data(self):
        result = analyze(identity("s3:*", "*"))
        self.assertIn("BROAD_S3_DATA_ACCESS", ids(result))
        self.assertIn("SERVICE_WILDCARD_S3", ids(result))

    def test_exact_get_object_on_star(self):
        result = analyze(identity("s3:GetObject", "*"))
        self.assertIsNotNone(by_id(result, "BROAD_S3_DATA_ACCESS"))

    def test_exact_put_object_on_star(self):
        result = analyze(identity("s3:PutObject", "*"))
        self.assertIsNotNone(by_id(result, "BROAD_S3_DATA_ACCESS"))

    def test_exact_delete_object_on_star(self):
        result = analyze(identity("s3:DeleteObject", "*"))
        self.assertIsNotNone(by_id(result, "BROAD_S3_DATA_ACCESS"))

    def test_scoped_get_object_no_broad_finding(self):
        result = analyze(identity("s3:GetObject", "arn:aws:s3:::my-bucket/prefix/*"))
        self.assertIsNone(by_id(result, "BROAD_S3_DATA_ACCESS"))


if __name__ == "__main__":
    unittest.main()
