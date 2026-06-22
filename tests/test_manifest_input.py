"""Input shapes accepted by the CLI: single, array, and manifest."""
import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from _engine import SCRIPT  # noqa: E402

FULL_ADMIN = {"Version": "2012-10-17",
              "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
CLEAN = {"Version": "2012-10-17",
         "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::b/*"}]}


def run(payload):
    proc = subprocess.run([sys.executable, SCRIPT], input=json.dumps(payload),
                          capture_output=True, text=True)
    return proc.returncode, json.loads(proc.stdout)["policies"]


class TestInputShapes(unittest.TestCase):
    def test_single_policy(self):
        code, policies = run(FULL_ADMIN)
        self.assertEqual(code, 0)
        self.assertEqual(len(policies), 1)
        self.assertEqual(policies[0]["summary"]["risk_level"], "CRITICAL")

    def test_array_of_policies(self):
        code, policies = run([FULL_ADMIN, CLEAN])
        self.assertEqual(len(policies), 2)
        self.assertEqual(policies[0]["summary"]["risk_level"], "CRITICAL")
        self.assertEqual(policies[1]["summary"]["risk_level"], "LOW")

    def test_manifest_with_source_labels(self):
        manifest = [
            {"source": "admin.json", "policy": FULL_ADMIN},
            {"source": "reader.json", "policy": CLEAN},
        ]
        code, policies = run(manifest)
        self.assertEqual(policies[0]["source"], "admin.json")
        self.assertEqual(policies[1]["source"], "reader.json")

    def test_manifest_with_policy_as_json_string(self):
        manifest = [{"source": "x", "policy": json.dumps(FULL_ADMIN)}]
        code, policies = run(manifest)
        self.assertEqual(policies[0]["summary"]["risk_level"], "CRITICAL")

    def test_manifest_independent_results(self):
        # No roll-up: each policy keeps its own status/risk.
        code, policies = run([{"source": "a", "policy": FULL_ADMIN},
                              {"source": "b", "policy": {"Statement": [42]}}])
        self.assertEqual(policies[0]["analysis_status"], "COMPLETE")
        self.assertEqual(policies[1]["analysis_status"], "INVALID")


if __name__ == "__main__":
    unittest.main()
