# Analysis Rubric

How to turn the deterministic engine output into a report.

When the engine returns several policies, write one independent assessment per
policy document (labeled by its `source`). Everything below applies **within a
single policy** — do not combine findings, severities, or recommendations across
policies, and do not produce an aggregate verdict.

## Grounding rules

- The engine findings are the factual basis. Summarize and organize them; only
  add a finding if the **policy text plainly supports it**. Never pad to look thorough.
- Analysis is based **only on the submitted policy**. You do not see policy
  attachments, SCPs, permission boundaries, session policies, resource
  configurations, or runtime usage. Do not assume any of it.
- Consolidate findings that share one root cause into a single item — don't list
  the same underlying problem twice in different words.
- Return an **empty list** for any section with no real findings.
- **Actions are the core signal.** The `Action` list is essentially always
  concrete and tells you the targeted service and capability — so analyze from the
  actions even when the `Resource` is an unresolved reference (`var.x`, `${...}`).
  An unknown resource limits confidence in *scope*, not in the findings: report
  them and note the scope is unknown rather than assuming `"*"`.

## The three lenses (do not repeat a finding across sections)

1. **Least privilege violations** — *scope only.* Are actions and resources
   scoped to the minimum necessary? Overly broad actions/resources, missing
   resource constraints where supported, unnecessary access to sensitive
   services. Does not describe impact or attack chains. Severity LOW/MEDIUM/HIGH.

2. **Privilege escalation paths** — *mechanism only.* Can permissions be chained
   to gain higher privileges than intended? Include **only** when permissions
   clearly enable it: `iam:PassRole`, `iam:CreatePolicyVersion`/
   `SetDefaultPolicyVersion`, `iam:AttachRolePolicy`/`PutRolePolicy`, broad
   `sts:AssumeRole`, or role-injection via a service that runs code under a passed
   role (Lambda/EC2/ECS/SageMaker/CloudFormation/Glue — and by judgment Batch,
   CodeBuild, EMR, etc.). The engine flags `PassRole` + compute provisioning even
   across **separate statements**. Describe the **specific capability** ("could
   allow attaching policies to any role"), not a blanket claim, and weigh the
   `PassRole` `Resource` scope — a tightly-scoped PassRole limits the escalation.
   Severity MEDIUM/HIGH/CRITICAL.

3. **Blast radius risks** — *impact only.* If these credentials were stolen, what
   is the realistic damage to data, services, or account integrity? Describe
   outcomes, not mechanisms or scope. Keep it conservative and scoped to what the
   policy directly enables. Severity LOW/MEDIUM/HIGH.

## Trust policies (`policy_type: trust`)

A trust policy answers *who may assume the role*, so the same three lenses are
driven by the `Principal` and its `Condition` scoping — not Action/Resource.
**Keep all three sections** for consistency; map the engine's trust findings:

- **Least privilege** — breadth of trust: `TRUST_PRINCIPAL_WILDCARD`,
  `TRUST_ACCOUNT_ROOT`, `TRUST_NOTPRINCIPAL`. The trust is broader than the
  specific principals that need it.
- **Escalation paths** — an *unintended* principal can assume the role and
  inherit its permissions: `TRUST_CROSS_ACCOUNT_NO_EXTERNALID` (confused deputy),
  `TRUST_FEDERATED_UNSCOPED` (e.g. any repo via OIDC), `TRUST_SAML_UNSCOPED`.
- **Blast radius** — *conditional note, not a combined verdict.* State that
  whoever can assume the role gains its **entire permission set**, and that the
  magnitude depends on the role's permission policies, which are evaluated
  **separately** (you do not connect them — see the no-roll-up rule above). If
  there are no trust findings, say the trust appears appropriately scoped.

A clean trust policy (specific role/user ARN, a service principal, or scoped
federation) has no findings → LOW. Do not flag the expected `sts:AssumeRole`
action or normal service principals.

## Cautious phrasing (required)

- Prefer "can enable", "may allow", "could permit", "materially increases the
  risk of" over absolutes like "allows", "achieves", "full compromise".
- Do **not** present hypothetical downstream impact as certain when it depends on
  unknown trust policies, role inventory, SCPs, boundaries, resource sensitivity,
  or runtime context.
- Never write "full privilege escalation path exists" / "full account compromise"
  unless the policy alone grants effectively unrestricted admin (`Action:"*"` and
  `Resource:"*"` with no conditions).
- Titles: one line, under ~8 words, no trailing punctuation, no absolute language.

## IAM semantics to respect

- Explicit `Deny` overrides `Allow`.
- `Condition` blocks may meaningfully restrict access — account for them.
- `NotAction` / `NotResource` broaden scope and need careful interpretation
  (the engine already flags them HIGH).
- Wildcard permissions significantly increase risk.

## Exclusions

- Do not flag standard read-only `describe`/`list`/`get`/`lookup`/`view`
  permissions unless combined with write, delete, or mutation actions.
- Do not surface findings about the **absence** of permissions — only flag what
  the policy explicitly allows that is dangerous.

## Voice

Write as a security engineer for a technical-but-not-specialist reader. Plain
language first. Avoid words like
"deterministic", "rule engine", "check", "mismatch" in the finished report.

## Recommendations

Actionable and specific — reference the exact action or resource pattern to fix.
Prioritize least privilege and scoping. Consolidate recommendations that share
the same root fix. Priority is LOW/MEDIUM/HIGH.

## Analysis limitations (always include)

Close with 1–3 items naming context you could not see, e.g.:
- "Policy attachment context (user, role, group) is unknown."
- "No visibility into SCPs or permission boundaries."
- "Actual resource usage and data sensitivity are not known."
