# Engine unit tests

Deterministic unit tests for `scripts/analyze_policy.py` (Python stdlib
`unittest`, no third-party dependencies). These are distinct from the Claude
skill evals in `../evals/`:

| Suite | Location | Tests |
|-------|----------|-------|
| Deterministic engine unit tests | `tests/` (here) | The rule engine's exact findings, severities, and statuses |
| Skill-triggering evals | `../evals/trigger_queries.json` | Whether the skill activates on the right prompts |
| Report-quality evals | `../evals/evals.json` | Whether Claude's written report meets the assertions |

## Run

```bash
python3 -m unittest discover -s tests        # from the skill root
# or
python3 -m pytest tests                       # if pytest is installed
```

## Coverage

| File | Covers |
|------|--------|
| `test_input_validation.py` | Malformed input → `INVALID` (never a clean `LOW`) |
| `test_identity_policies.py` | Identity findings: positive/negative/scoped/wildcard, categories, titles |
| `test_trust_policies.py` | Trust findings incl. wildcard-subject OIDC regression |
| `test_escalation_paths.py` | PassRole + compute, cross-statement chains, policy mutation |
| `test_conditions.py` | Effective-condition operators; `_all_actions_read_only("*")` regression |
| `test_s3_classification.py` | S3 object-data classification corrections |
| `test_deduplication.py` | `FULL_ADMIN` consolidation (exact-output regression) |
| `test_manifest_input.py` | Single / array / manifest input shapes |
| `test_exit_codes.py` | Process exit codes (malformed policy = result, not failure) |
