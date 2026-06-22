---
name: iam-policy-analyzer
description: Analyze one or more AWS IAM policies for security risk — least privilege violations, privilege escalation paths, and blast radius — and produce a plain-language report with prioritized recommendations per policy. Use when the user pastes or points to IAM policies / trust policies / inline policies, or to a file that defines them (any Terraform .tf file using jsonencode/heredoc/aws_iam_policy_document, CloudFormation templates, multiple JSON policies), and asks whether they are safe, over-permissioned, escalatable, or follow least privilege. Not for SCPs, resource policies evaluated against principals, or live account auditing.
---

# IAM Policy Analyzer

Statically assess one or more AWS IAM policy documents and report each one's security posture. The analysis sees **only the policy text** — never assume attachment context, SCPs, permission boundaries, role inventory, or runtime usage.

**Unit of analysis is the whole policy document** (its `Version` plus the entire `Statement` array, however many statement blocks / `Sid`s it contains). When several policies are present, **review each one independently** — do not combine or roll up risk across policies.

## Workflow

1. **Identify and extract every policy document.** A single pasted policy needs no extraction. If the input *defines* policies (any Terraform `.tf` file, CloudFormation template, several JSON policies, etc.), extract each to standard IAM-policy JSON per `reference/extraction.md` and build a **manifest** — a JSON array of `{"source": "<where it came from>", "policy": <policy>}`. Follow extraction.md's rule for unresolved references: a policy whose load-bearing fields (`Action`/`Effect`/`Principal`) are unresolved is **un-analyzable**, not clean. Never fabricate, silently drop, or over-claim a policy.

2. **Run the deterministic engine** — it identifies the supported high-risk patterns and gives reproducible findings that anchor the report; never skip it. Pass policy files directly, or pipe the manifest in:
   ```bash
   python3 scripts/analyze_policy.py policy1.json policy2.json
   # or, with the manifest you built during extraction:
   echo "$MANIFEST_JSON" | python3 scripts/analyze_policy.py
   ```
   It returns `{"policies": [ {source, policy_type, valid, analysis_status, parse_error, findings[], summary.risk_level, explicit_deny_present, ...}, ... ]}`, one entry per policy document. **Check `analysis_status` before `risk_level` — only `COMPLETE` carries a real risk level. `INVALID` (malformed — `risk_level` null, see `invalid_statements`) and `NOT_ANALYZED` (out-of-scope resource policy) must never be reported as clean/LOW.** See `reference/analysis.md` (Part 1) for the full output schema, every finding `id`, the categories, and severity rules.

3. **Reason and phrase the report**, **per policy**, using `reference/analysis.md` (Part 2): anchor every finding to the engine output (add one only if the policy text plainly supports it), apply the three lenses (least privilege / escalation / blast radius), cautious phrasing, and the read-only exclusions. Do **not** invent context or claim definitive compromise unless that policy alone grants unrestricted admin (`Action:"*"` + `Resource:"*"`, no conditions).

4. **Emit the report** following `templates/report.md`: one independent assessment block per policy (labeled by its `source`), each with the three analysis sections, prioritized recommendations, and an Analysis Limitations list naming the context you could not see. Do not produce a combined or aggregate verdict across policies.

## Grounding (optional)

If an AWS documentation tool is available in the session (e.g. the AWS MCP `search_documentation` / `read_documentation`), use it to verify uncertain specifics rather than relying on memory — condition-key semantics, whether a service action passes a role, exact action names, current best practice. Use **only** these read-only documentation lookups. **Never** call live-account AWS APIs or run AWS commands: this skill performs **static analysis of the policy text only and must not connect to any AWS account.** If no documentation tool is available, fall back to training knowledge — the skill is fully self-contained without it.

## Maintenance

`scripts/analyze_policy.py` is the behavioral source of truth; `reference/analysis.md`
documents it (findings, severities, and how to write the report). If you change
one, update the other so they stay in sync.
