---
name: iam-policy-analyzer
description: Analyze one or more AWS IAM policies for security risk — least privilege violations, privilege escalation paths, and blast radius — and produce a plain-language report with prioritized recommendations per policy. Use when the user pastes or points to IAM policies / trust policies / inline policies, or to a file that defines them (any Terraform .tf file using jsonencode/heredoc/aws_iam_policy_document, CloudFormation templates, multiple JSON policies), and asks whether they are safe, over-permissioned, escalatable, or follow least privilege. Not for SCPs, resource policies evaluated against principals, or live account auditing.
---

# IAM Policy Analyzer

Statically assess one or more AWS IAM policy documents and report each one's security posture. The analysis sees **only the policy text** — never assume attachment context, SCPs, permission boundaries, role inventory, or runtime usage.

**Unit of analysis is the whole policy document** (its `Version` plus the entire `Statement` array, however many statement blocks / `Sid`s it contains). When several policies are present, **review each one independently** — do not combine or roll up risk across policies.

## Workflow

1. **Identify and extract every policy document.** A single pasted policy needs no extraction. If the input *defines* policies (any Terraform `.tf` file, CloudFormation template, several JSON policies, etc.), extract each to standard IAM-policy JSON per `reference/extraction.md` and build a **manifest** — a JSON array of `{"source": "<where it came from>", "policy": <policy>}`. Follow extraction.md's rule for unresolved references: a policy whose load-bearing fields (`Action`/`Effect`/`Principal`) are unresolved is **un-analyzable**, not clean. Never fabricate, silently drop, or over-claim a policy.

2. **Run the deterministic engine** — the factual ground truth; never skip it. Pass policy files directly, or pipe the manifest in:
   ```bash
   python3 scripts/analyze_policy.py policy1.json policy2.json
   # or, with the manifest you built during extraction:
   echo "$MANIFEST_JSON" | python3 scripts/analyze_policy.py
   ```
   It returns `{"policies": [ {source, policy_type, valid, parse_error, findings[], summary.risk_level}, ... ]}`, one entry per policy document. `policy_type` is `identity`, `trust`, or `resource`. A `resource` entry is a *service* resource-based policy (S3/KMS/SQS/SNS/Lambda/DynamoDB) — **out of scope**: it has `risk_level: NOT_ANALYZED`, no findings, and a `note`; report it as "not analyzed (resource-based policy, out of scope)" and move on. Each finding has an `id`, `severity`, `title`, `description`, and `statement_index`. For any entry where `valid` is `false`, report its `parse_error` for that source and continue with the others. See `reference/finding-catalog.md` for what each finding `id` means and the severity rules.

3. **Reason and phrase the report** using `reference/analysis-rubric.md`, **per policy**. Anchor every finding to the engine output; you may add a finding only if the policy text plainly supports it. Apply the three lenses (least privilege / escalation / blast radius), cautious phrasing, and the read-only exclusions. For a `trust` policy, use the rubric's **Trust policies** section — the lenses are driven by the `Principal` and its `Condition`, and blast radius is a conditional note (it depends on the role's permission policies, evaluated separately — never combine them). Do **not** invent context or claim definitive compromise unless that policy alone grants unrestricted admin (`Action:"*"` + `Resource:"*"`, no conditions).

4. **Emit the report** following `templates/report.md`: one independent assessment block per policy (labeled by its `source`), each with the three analysis sections, prioritized recommendations, and an Analysis Limitations list naming the context you could not see. Do not produce a combined or aggregate verdict across policies.

## Grounding (optional)

If an AWS documentation tool is available in the session (e.g. the AWS MCP `search_documentation` / `read_documentation`), use it to verify uncertain specifics rather than relying on memory — condition-key semantics, whether a service action passes a role, exact action names, current best practice. Use **only** these read-only documentation lookups. **Never** call live-account AWS APIs or run AWS commands: this skill performs **static analysis of the policy text only and must not connect to any AWS account.** If no documentation tool is available, fall back to training knowledge — the skill is fully self-contained without it.

## When NOT to flag

Standard read-only `describe`/`list`/`get` permissions are expected in audit roles — do not flag them unless combined with write, delete, or mutation actions. Do not surface the *absence* of permissions as a finding. In a trust policy, the `sts:AssumeRole` action and normal service principals (`ec2.amazonaws.com`, etc.) are expected — don't flag them; the risk is in a broad or unscoped `Principal`.

## Maintenance

The deterministic engine (`scripts/analyze_policy.py`), the finding catalog
(`reference/finding-catalog.md`), and the rubric (`reference/analysis-rubric.md`)
describe the same rule set. If you change one, update the others so the
documented severity logic stays in sync with the code.
