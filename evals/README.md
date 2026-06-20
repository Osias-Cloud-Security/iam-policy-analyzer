# Evals

Starter evaluation set for the `iam-policy-analyzer` skill, following the
[agentskills.io](https://agentskills.io/skill-creation/evaluating-skills) eval
guidance. Two independent things are tested here.

## 1. Output quality — `evals.json`

Seven test cases, each a realistic prompt plus an `expected_output` and
objective `assertions`, covering the skill's distinct branches:

| id | fixture | exercises |
|----|---------|-----------|
| 1 | `files/full_admin.json` | full-admin identity policy → CRITICAL |
| 2 | `files/passrole_escalation.json` | PassRole + compute escalation path → CRITICAL |
| 3 | `files/readonly_audit.json` | clean read-only audit role → LOW (false-positive guard) |
| 4 | `files/wildcard_trust.json` | wildcard-principal trust policy → CRITICAL |
| 5 | `files/s3_bucket_policy.json` | resource-based policy → out of scope / not analyzed |
| 6 | `files/roles.tf` | extract two policies from Terraform, score each independently |
| 7 | `files/s3_read_glob.json` | `s3:Get*` on `*` → HIGH (wildcard read glob covers s3:GetObject; not excused as read-only) |

Run each prompt twice — once with the skill, once without — in a fresh context,
then grade the output against the case's `assertions` (PASS/FAIL with evidence).
The expected verdicts above were confirmed against the current rule engine.

## 2. Triggering — `trigger_queries.json`

Twenty labelled prompts (ten `should_trigger`, ten `should_not_trigger`) for
testing whether the `description` activates the skill on the right requests. The
negatives are deliberate near-misses that share keywords but need something
else: policy *authoring*, SCPs, resource-based policies, live-account auditing,
format conversion, and conceptual questions. Run each a few times and compute a
trigger rate (pass threshold 0.5).
