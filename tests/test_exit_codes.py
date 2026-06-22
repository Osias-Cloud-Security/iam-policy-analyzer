"""Process exit codes. A malformed policy is a RESULT (exit 0), not a failure;
non-zero is reserved for the script being unable to do its job."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from _engine import SCRIPT  # noqa: E402

EXIT_OK = 0
EXIT_NO_INPUT = 1
EXIT_READ_ERROR = 2


class TestExitCodes(unittest.TestCase):
    def test_valid_policy_exits_ok(self):
        policy = json.dumps({"Version": "2012-10-17",
                             "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        proc = subprocess.run([sys.executable, SCRIPT], input=policy,
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, EXIT_OK)

    def test_malformed_policy_still_exits_ok(self):
        # INVALID is a legitimate analysis result carried in the JSON.
        proc = subprocess.run([sys.executable, SCRIPT], input='{"Statement": [42]}',
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, EXIT_OK)
        self.assertEqual(json.loads(proc.stdout)["policies"][0]["analysis_status"], "INVALID")

    def test_empty_stdin_is_no_input(self):
        proc = subprocess.run([sys.executable, SCRIPT], input="   ",
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, EXIT_NO_INPUT)

    def test_unreadable_file_is_read_error(self):
        missing = os.path.join(tempfile.gettempdir(), "iam_analyzer_does_not_exist_xyz.json")
        proc = subprocess.run([sys.executable, SCRIPT, missing],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, EXIT_READ_ERROR)


if __name__ == "__main__":
    unittest.main()
