"""Shared test helpers — import the engine and provide small conveniences.

Importable under both `python3 -m unittest discover -s tests` and `pytest`.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import analyze_policy as ap  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "scripts", "analyze_policy.py")


def analyze(policy):
    """Analyze a single policy (dict or JSON string); return the result dict."""
    text = policy if isinstance(policy, str) else json.dumps(policy)
    return ap.analyze_policy_document(text)


def ids(result):
    """Sorted list of finding ids in a result."""
    return sorted(f["id"] for f in result["findings"])


def by_id(result, finding_id):
    """First finding with the given id, or None."""
    for finding in result["findings"]:
        if finding["id"] == finding_id:
            return finding
    return None


def risk(result):
    return result["summary"]["risk_level"]
