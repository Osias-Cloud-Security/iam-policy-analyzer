# Finding Catalog

What each deterministic finding `id` from `scripts/analyze_policy.py` means, and
how severity is assigned. Each finding carries the `statement_index` it came from.

## Policy classification (`policy_type`)

The engine classifies each document and routes it to the matching rule set. The
result carries a `policy_type`:

- **`identity`** — no `Principal` element. Permissions attached to a user/role/
  group. Scored by the identity findings below (Action/Resource based).
- **`trust`** — has a `Principal` and only `sts:Assume*` actions. A role trust
  policy. Scored by the trust findings below (Principal/Condition based).
- **`resource`** — has a `Principal` and other actions: a *service* resource-based
  policy (S3 bucket, KMS key, SQS, SNS, Lambda, DynamoDB, …). **Out of scope** —
  this skill is strictly IAM identity + role trust policies. The engine does not
  analyze it: it returns `risk_level: NOT_ANALYZED`, no findings, and a `note`.
  Report it as "not analyzed (resource-based policy, out of scope)."

## Severity assignment

Most identity rules escalate severity when the statement is scoped to
`Resource: "*"`; most trust rules escalate when the principal is broad and no
scoping `Condition` is present. The overall `summary.risk_level` is the
**highest** finding severity present (CRITICAL > HIGH > MEDIUM > LOW); a policy
with no findings is `LOW`.

A statement is only evaluated when its `Effect` is `Allow`. `Deny` statements are
skipped (they reduce, not grant, access). A finding's `statement_index` points to
the offending statement; **`-1` means a policy-level finding** that arises from
permissions combined **across multiple statements** (IAM unions a policy's
statements), not from one block.

## Identity findings (`policy_type: identity`)

| id | Trigger | Severity |
|----|---------|----------|
| `FULL_ADMIN` | `Action: "*"` **and** `Resource: "*"` in one statement | CRITICAL |
| `WILDCARD_ACTIONS_AND_RESOURCES` | Any wildcard action (`*` inside the action) + `Resource:"*"`, and not all actions are read-only | CRITICAL |
| `IAM_PASSROLE` | `iam:PassRole` present | CRITICAL if `Resource:"*"`, else HIGH |
| `IAM_POLICY_MUTATION` | Any policy-mutation action (`AttachRolePolicy`, `PutRolePolicy`, `CreatePolicyVersion`, etc.) | CRITICAL if `CreatePolicyVersion`/`SetDefaultPolicyVersion`, else HIGH |
| `COMPUTE_ROLE_INJECTION` | `iam:PassRole` **combined with** a compute-provisioning action that runs code under a passed role (`lambda:CreateFunction`, `ec2:RunInstances`, `cloudformation:CreateStack`, `ecs:RegisterTaskDefinition`, `sagemaker:Create*`, `glue:CreateJob`, …) — whether in the **same statement** or **split across separate statements** of the policy (`statement_index: -1` = cross-statement) | CRITICAL |
| `COMPUTE_CONTROL` | A compute-provisioning action (as above) **without** PassRole in the policy | HIGH if `Resource:"*"`, else MEDIUM |
| `SERVICE_WILDCARD_<SVC>` | `<svc>:*` for a sensitive service (`iam`, `kms`, `secretsmanager`, `ssm`, `s3`, `ec2`, `lambda`, `cloudformation`, `organizations`, `sts`) | HIGH |
| `STS_ASSUME_ROLE` | `sts:AssumeRole` / `…WithSAML` / `…WithWebIdentity` | HIGH if `Resource:"*"`, else MEDIUM |
| `SENSITIVE_DATA_ACCESS` | Secret/parameter/decrypt reads (`secretsmanager:GetSecretValue`, `ssm:GetParameter(s)`, `kms:Decrypt`) | HIGH if `Resource:"*"`, else MEDIUM |
| `BROAD_S3_DATA_ACCESS` | An S3 object data action (`s3:GetObject`/`PutObject`/`DeleteObject`) **or** a grant of the S3 service wildcard (`s3:*` or `*`), with `Resource:"*"`. Read-only S3 actions (e.g. `s3:ListAllMyBuckets`) do **not** trigger this on their own. | HIGH |
| `WRITE_ON_ALL_RESOURCES` | Any non-read-only action with `Resource:"*"` | HIGH |
| `ALLOW_NOTACTION` | An `Allow` statement uses `NotAction` | HIGH |
| `ALLOW_NOTRESOURCE` | An `Allow` statement uses `NotResource` | HIGH |

## Trust findings (`policy_type: trust`)

Risk in a trust policy lives in **who is trusted** (`Principal`) and **how the
trust is scoped** (`Condition`). The `Action` is almost always `sts:AssumeRole`-
family and is *expected* — it is not a finding. A clean trust policy (a specific
role/user ARN, a service principal, or a scoped federation) produces **no
findings → LOW**.

### Effective scoping (condition-value inspection)

A `Condition` only counts as scoping if it **effectively** narrows access. The
engine inspects operators and values, not just key presence — a condition is
**ignored** (does not downgrade severity) when it is:

- a **negative** operator (`StringNotEquals`, `ArnNotEquals`, …) — scopes *out*, not in;
- an **`…IfExists`** operator — dodged when the key is absent from the request;
- a **`ForAllValues:`** set match — vacuous-truth bypass when the key is absent;
- a **wildcard value** (`*`/`?`) for the key — e.g. `ArnLike aws:PrincipalArn = …::*:role/*` restricts nothing.

Effective scoping is then tiered:

- **precise** — names a specific principal/resource: `aws:PrincipalArn` (a
  non-root ARN), `aws:userid`, `aws:username`, `aws:SourceArn`.
- **broad** — account/org/network only: `aws:PrincipalOrgID`/`OrgPaths`,
  `aws:PrincipalAccount`, `sts:ExternalId`, `aws:Source{Account,OrgID,OrgPaths}`,
  MFA, IP/VPC, an account-root `aws:PrincipalArn`.

"Confused-deputy guard" = an **effective** key in `CONFUSED_DEPUTY_GUARD_KEYS`
(`sts:ExternalId`, `aws:PrincipalOrgID`/`OrgPaths`, `aws:Source*`).

| id | Trigger | Lens | Severity |
|----|---------|------|----------|
| `TRUST_PRINCIPAL_WILDCARD` | `Principal` is `"*"` or `{"AWS":"*"}` | least-privilege | **CRITICAL** if no effective scoping · **HIGH** if broad · **MEDIUM** if precise (wildcard-plus-condition is fragile; never auto-LOW) |
| `TRUST_ACCOUNT_ROOT` | AWS principal is an account-root ARN (`…:root`) or bare 12-digit account id (trusts the whole account) | least-privilege | HIGH if no effective scoping; MEDIUM if scoped |
| `TRUST_CROSS_ACCOUNT_NO_EXTERNALID` | Account-wide AWS principal (above) **and** no effective confused-deputy guard. Does not fire for wildcard (already covered) | escalation | HIGH |
| `TRUST_FEDERATED_UNSCOPED` | Web-identity/OIDC federation (`sts:AssumeRoleWithWebIdentity` or an `:oidc-provider/` principal) **and** no `:sub`/`:aud` Condition present | escalation | HIGH |
| `TRUST_SAML_UNSCOPED` | SAML federation (`sts:AssumeRoleWithSAML` or a `:saml-provider/` principal) **and** no `saml:aud` Condition present | escalation | MEDIUM |
| `TRUST_NOTPRINCIPAL` | An `Allow` statement uses `NotPrincipal` (trusts everyone *except* the listed principals — AWS recommends never doing this) | least-privilege | **CRITICAL** if no effective scoping; **HIGH** if scoped |

Service principals (`ec2.amazonaws.com`, `lambda.amazonaws.com`, …) are normal
and not flagged. The federation `:sub`/`:aud` and `saml:aud` checks are
presence-based (a repo-scoped `:sub` with a branch wildcard is legitimately
scoped), so value inspection is not applied there.

**On `ForAllValues` and multi-key conditions:** the classifier never credits a
`ForAllValues:` set match as scoping — a bare `ForAllValues` evaluates *true*
when the key is absent, so it is vacuously bypassable. Conditions in a block are
AND-ed, so crediting only the most-restrictive *effective* key is correct. This
errs toward *over*-flagging, never a false clean. The lone over-rated case is a
`ForAllValues` correctly paired with a `Null …:false` guard (rare here) — account
for it in judgment if you see one.

## Notes for the model layer

- A single statement commonly produces several findings (e.g. an admin statement
  fires `FULL_ADMIN` plus every `SERVICE_WILDCARD_*`). When writing the report,
  **consolidate** these into one least-privilege/blast-radius point per root cause
  rather than echoing each row — see `analysis-rubric.md`.
- **The deterministic rules are seed signal, not the whole analysis.** They cover
  the high-confidence, well-known cases; they are deliberately *not* exhaustive.
  Apply your own judgment from AWS documentation and training to extend them — e.g.
  the compute role-injection list names Lambda/EC2/ECS/SageMaker/CloudFormation/
  Glue, but **any** service action that runs code under a *passed* role (Batch,
  CodeBuild, EMR, Data Pipeline, Cloud9, Step Functions, …) is the same escalation
  class when combined with `iam:PassRole`. Likewise weigh the `PassRole` `Resource`
  scope: a tightly-scoped `PassRole` materially limits the escalation.
- **`iam:CreatePolicy` is intentionally *not* treated as escalation on its own** —
  it creates an unattached policy and grants nothing until an `Attach*` action
  (already flagged) attaches it. The standalone IAM-mutation primitives are
  `iam:CreatePolicyVersion` / `SetDefaultPolicyVersion` (they change an
  already-attached policy).
- "Read-only" = the action verb starts with `describe`, `get`, `list`, `lookup`,
  or `view`. `*` is treated as non-read-only.
- For identity policies, the engine does not inspect `Condition` *values* beyond
  noting presence; for trust policies it specifically checks for the scoping and
  confused-deputy condition keys above. When a statement has conditions, temper
  severity language accordingly.
- **Actions are the core signal.** Findings hold even when the `Resource` is an
  unresolved reference — an unknown resource lowers confidence in *scope*, not in
  the finding (the engine never treats it as `"*"`). Report the action-driven
  findings and note the resource scope is unknown.
- **Trust blast radius is conditional.** A trust policy does not define the role's
  permissions, so its blast radius = "whoever can now assume it gains the role's
  full permission set," whose magnitude lives in the role's *separate* permission
  policies. Report it as a conditional note, not a combined verdict.
