# IAM Analysis Reference

Single source of truth for **(1)** what the deterministic engine
(`scripts/analyze_policy.py`) emits and what each finding means, and **(2)** how
to turn that output into a per-policy report. The engine code is the behavioral
source of truth; this doc documents it.

---

# Part 1 — Engine output

What each finding `id` means and how severity is assigned. Each finding carries
the `statement_index` it came from.

## What the engine does NOT do (read first)

`effective_permissions_calculated` is always `false` — the engine lints Allow
grants, it does not compute net permissions.

## Policy classification (`policy_type`)

The engine classifies each document and routes it to the matching rule set:

- **`identity`** — no `Principal` element. Permissions attached to a user/role/
  group. Scored by the identity findings below (Action/Resource based).
- **`trust`** — has a `Principal` and only `sts:Assume*` actions. A role trust
  policy. Scored by the trust findings below (Principal/Condition based).
- **`resource`** — has a `Principal` and other actions: a *service* resource-based
  policy (S3 bucket, KMS key, SQS, SNS, Lambda, DynamoDB, …). **Out of scope** —
  this skill is strictly IAM identity + role trust policies. The engine returns
  `analysis_status: NOT_ANALYZED`, `risk_level: null`, no findings, and a `note`.
  Report it as "not analyzed (resource-based policy, out of scope)."

## Analysis status (`analysis_status`)

Separate from risk. Always check it before reading `summary.risk_level`:

- **`COMPLETE`** — every statement was structurally analyzable; `risk_level` is
  `LOW`/`MEDIUM`/`HIGH`/`CRITICAL`.
- **`INVALID`** — the document is malformed (bad JSON, no `Statement`) **or** a
  statement violates the IAM schema: not a JSON object, missing/invalid `Effect`,
  neither `Action` nor `NotAction`, neither `Resource` nor `NotResource` (identity)
  / neither `Principal` nor `NotPrincipal` (trust), or an invalid type for
  `Action`/`Resource`/`Principal`/`Condition`. AWS would reject such a policy, so
  the engine **stops and does not score a subset** — `risk_level` is `null`,
  findings is empty, and `invalid_statements` lists each offending
  `{statement_index, reason}`. A malformed policy is **not** LOW/clean.
- **`NOT_ANALYZED`** — out-of-scope resource-based policy (above); `risk_level` null.

The engine never returns PARTIAL. An unresolved-but-valid policy (Terraform `var`,
CFN intrinsic) is handled at extraction (`reference/extraction.md`) and must not reach the
engine as a half-policy. A statement the engine simply has no *rule* for is still
`COMPLETE` — "malformed" means a schema violation, not "unsupported."

## Finding fields

Each finding carries an `id`, a `category`, a `severity`, a `title`, a
`description`, and a `statement_index`. The `category` separates genuine defects
from powerful-but-scoped capabilities:

- **`SECURITY_RISK`** — a broad/unsafe grant that is a defect on its own
  (`FULL_ADMIN`, wildcard combos, `NotAction`/`NotResource`, wildcard/account-root
  trust).
- **`BROAD_PERMISSION`** — wildcard breadth (`SERVICE_WILDCARD_*`, broad S3 data).
- **`PRIVILEGE_ESCALATION`** — can be chained to higher privilege (`IAM_PASSROLE`,
  `IAM_POLICY_MUTATION`, `CREDENTIAL_ESCALATION`, `BOUNDARY_MUTATION`,
  `COMPUTE_ROLE_INJECTION`, unscoped trust/federation).
- **`SENSITIVE_CAPABILITY`** — a sensitive but **scoped** capability (a scoped
  `sts:AssumeRole`, secret read, or compute action). Review, not a vulnerability —
  do not describe it as a defect.

`explicit_deny_present` (top-level) flags that the policy has `Deny` statements
the engine did **not** evaluate.

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
| `CREDENTIAL_ESCALATION` | A credential-access primitive — `iam:CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`, `AddUserToGroup`, `UpdateAssumeRolePolicy` (obtain another principal's credentials, no policy edit needed) | HIGH if `Resource:"*"`, else MEDIUM |
| `BOUNDARY_MUTATION` | A permissions-boundary action — `iam:Put`/`Delete` `User`/`Role` `PermissionsBoundary`. A boundary caps an entity's max permissions; loosening/removing one lifts the cap | HIGH if `Resource:"*"`, else MEDIUM |
| `COMPUTE_ROLE_INJECTION` | `iam:PassRole` **combined with** a compute-provisioning action that runs code under a passed role (`lambda:CreateFunction`, `ec2:RunInstances`, `cloudformation:CreateStack`, `ecs:RegisterTaskDefinition`, `sagemaker:Create*`, `glue:CreateJob`, `codebuild:CreateProject`, `batch:RegisterJobDefinition`, `emr:RunJobFlow`, `states:CreateStateMachine`, `datapipeline:PutPipelineDefinition`) — whether in the **same statement** or **split across separate statements** of the policy (`statement_index: -1` = cross-statement) | CRITICAL |
| `COMPUTE_CONTROL` | A compute-provisioning action (as above) **without** PassRole in the policy | HIGH if `Resource:"*"`, else MEDIUM |
| `SERVICE_WILDCARD_<SVC>` | `<svc>:*` for a sensitive service (`iam`, `kms`, `secretsmanager`, `ssm`, `s3`, `ec2`, `lambda`, `cloudformation`, `organizations`, `sts`) | HIGH |
| `STS_ASSUME_ROLE` | `sts:AssumeRole` / `…WithSAML` / `…WithWebIdentity` | HIGH if `Resource:"*"`, else MEDIUM |
| `SENSITIVE_DATA_ACCESS` | Secret/parameter/decrypt reads (`secretsmanager:GetSecretValue`, `ssm:GetParameter(s)`, `kms:Decrypt`) at any scope; **or** a bulk data-plane read (`dynamodb:GetItem`/`Query`/`Scan`/`BatchGetItem`, `lambda:GetFunction`) **only at `Resource:"*"`** | HIGH if `Resource:"*"`, else MEDIUM |
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
| `TRUST_FEDERATED_UNSCOPED` | Web-identity/OIDC federation (`sts:AssumeRoleWithWebIdentity` or an `:oidc-provider/` principal) with no **effective** `:sub`/`:aud` Condition — absent, or present but a bare wildcard value (`"*"`) | escalation | HIGH |
| `TRUST_SAML_UNSCOPED` | SAML federation (`sts:AssumeRoleWithSAML` or a `:saml-provider/` principal) **and** no `saml:aud` Condition present | escalation | MEDIUM |
| `TRUST_NOTPRINCIPAL` | An `Allow` statement uses `NotPrincipal` (trusts everyone *except* the listed principals — AWS recommends never doing this) | least-privilege | **CRITICAL** if no effective scoping; **HIGH** if scoped |

Service principals (`ec2.amazonaws.com`, `lambda.amazonaws.com`, …) are normal
and not flagged. The OIDC `:sub`/`:aud` check credits any value except a bare
wildcard (`"*"`) — a repo-scoped `:sub` with a branch wildcard
(`repo:org/app:ref:refs/heads/*`) is legitimately scoped and stays clean, but a
`:sub` of `"*"` is treated as unscoped. The SAML `saml:aud` check is
presence-based.

**On `ForAllValues` and multi-key conditions:** the classifier never credits a
`ForAllValues:` set match as scoping — a bare `ForAllValues` evaluates *true*
when the key is absent, so it is vacuously bypassable. Conditions in a block are
AND-ed, so crediting only the most-restrictive *effective* key is correct. This
errs toward *over*-flagging, never a false clean. The lone over-rated case is a
`ForAllValues` correctly paired with a `Null …:false` guard (rare here) — account
for it in judgment if you see one.

## Engine notes

- The engine already consolidates `FULL_ADMIN`: when a statement is
  `Action:"*"` + `Resource:"*"`, the breadth findings it covers
  (`SERVICE_WILDCARD_*`, `BROAD_S3_DATA_ACCESS`, `WILDCARD_ACTIONS_AND_RESOURCES`,
  `WRITE_ON_ALL_RESOURCES`) are dropped for that statement and the affected
  services are folded into `FULL_ADMIN.metadata.affected_services`.
- **The deterministic rules are seed signal, not the whole analysis.** They cover
  the high-confidence, well-known cases; they are deliberately *not* exhaustive.
  Apply your own judgment from AWS documentation and training to extend them — e.g.
  the compute role-injection list now covers Lambda/EC2/ECS/SageMaker/CloudFormation/
  Glue/CodeBuild/Batch/EMR/Step Functions/Data Pipeline, but **any** other service
  action that runs code under a *passed* role (AppRunner, Cloud9, …) is the same
  escalation class when combined with `iam:PassRole`. Likewise weigh the `PassRole`
  `Resource` scope: a tightly-scoped `PassRole` materially limits the escalation.
- **`iam:CreatePolicy` is intentionally *not* treated as escalation on its own** —
  it creates an unattached policy and grants nothing until an `Attach*` action
  (already flagged) attaches it. The standalone IAM-mutation primitives are
  `iam:CreatePolicyVersion` / `SetDefaultPolicyVersion` (they change an
  already-attached policy).
- **"Read-only"** (for the write-on-`*` gate) = the action verb starts with
  `describe`, `get`, `list`, `lookup`, or `view`; `*` is non-read-only. This
  prefix test is about **control-plane/metadata** reads. **Data-plane reads**
  (reading object/item/secret *contents*) are NOT safe just because the verb is
  `Get`/`Query`/`Scan` — the engine floors the common ones via
  `SENSITIVE_DATA_ACCESS` (at `Resource:"*"`), but judge others (e.g.
  `s3:GetObject*` outside the S3 rule, service data reads) by their effect, not
  their prefix.
- **Escalation coverage is not exhaustive.** `CREDENTIAL_ESCALATION` covers the
  five well-known IAM credential primitives only; ARN-embedded wildcards (e.g.
  `Resource: ".../user/*"`) read as scoped here — treat them as broad by judgment.
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

---

# Part 2 — Writing the report

> **GATE — read before writing anything about a policy.**
> Check `analysis_status` first, every time:
> - `COMPLETE` → assess normally (everything below applies).
> - `INVALID` → malformed policy AWS would reject. Do **not** score it. Name each `invalid_statements` entry (index + reason) and ask the user to fix and resubmit.
> - `NOT_ANALYZED` → out-of-scope resource-based policy. Report as out of scope, no risk rating.
>
> **A non-`COMPLETE` policy is never LOW, never clean.** Only after this gate passes do the three lenses below apply.

When the engine returns several policies, write one independent assessment per
policy document (labeled by its `source`). Everything below applies **within a
single policy** — do not combine findings, severities, or recommendations across
policies, and do not produce an aggregate verdict.

## Grounding rules

- **Check `analysis_status` first** (see Part 1). Only write a risk assessment
  when it is `COMPLETE`. `INVALID` → report that the policy is malformed and was
  not scored, name the offending statement(s) from `invalid_statements`, and ask
  the user to fix and resubmit (do **not** call it LOW/clean). `NOT_ANALYZED` →
  report as out of scope.
- The engine findings are the reproducible basis the report is built on. Summarize
  and organize them; only add a finding if the **policy text plainly supports it**.
  Never pad to look thorough.
- **The engine lints Allow grants only.** When `explicit_deny_present` is true,
  note that the policy also has `Deny` statements whose net effect was not
  evaluated, so a flagged Allow may be narrowed by a Deny.
- Analysis is based **only on the submitted policy** — you do not see attachments,
  SCPs, permission boundaries, session policies, resource configs, or runtime
  usage. Do not assume any of it.
- Consolidate findings that share one root cause into a single item — don't list
  the same underlying problem twice in different words. Return an **empty list**
  for any section with no real findings.
- Actions are the core signal (Part 1): analyze from the actions even when the
  `Resource` is unresolved; note scope is unknown rather than assuming `"*"`.

## The three lenses (do not repeat a finding across sections)

1. **Least privilege violations** — *scope only.* Are actions and resources scoped
   to the minimum necessary? Overly broad actions/resources, missing resource
   constraints, unnecessary access to sensitive services. No impact or attack
   chains. Severity LOW/MEDIUM/HIGH.

2. **Privilege escalation paths** — *mechanism only.* Can permissions be chained
   to gain higher privilege than intended? Include **only** when permissions
   clearly enable it: `iam:PassRole`, `iam:CreatePolicyVersion`/
   `SetDefaultPolicyVersion`, `iam:AttachRolePolicy`/`PutRolePolicy`, broad
   `sts:AssumeRole`, credential-access primitives (`iam:CreateAccessKey`,
   `Create`/`UpdateLoginProfile`, `AddUserToGroup`, `UpdateAssumeRolePolicy` —
   escalation only when the target can be more privileged, i.e. broad `Resource`),
   permissions-boundary mutation (`iam:Put`/`Delete` `User`/`Role`
   `PermissionsBoundary` — lifts the max-permissions cap), or role-injection via a
   service that runs code under a passed role. Describe the
   **specific capability** ("could allow attaching policies to any role"), not a
   blanket claim, and weigh `Resource` scope — a tightly-scoped PassRole or
   credential action limits the escalation. Severity MEDIUM/HIGH/CRITICAL.

3. **Blast radius risks** — *impact only.* If these credentials were stolen, what
   is the realistic damage to data, services, or account integrity? Describe
   outcomes, not mechanisms or scope. Conservative, scoped to what the policy
   directly enables. Severity LOW/MEDIUM/HIGH.

## Trust policies (`policy_type: trust`)

A trust policy answers *who may assume the role*, so the same three lenses are
driven by the `Principal` and its `Condition` scoping. **Keep all three sections**:

- **Least privilege** — breadth of trust: `TRUST_PRINCIPAL_WILDCARD`,
  `TRUST_ACCOUNT_ROOT`, `TRUST_NOTPRINCIPAL`.
- **Escalation paths** — an *unintended* principal can assume the role and inherit
  its permissions: `TRUST_CROSS_ACCOUNT_NO_EXTERNALID` (confused deputy),
  `TRUST_FEDERATED_UNSCOPED` (e.g. any repo via OIDC), `TRUST_SAML_UNSCOPED`.
- **Blast radius** — *conditional note, not a combined verdict.* Whoever can assume
  the role gains its **entire permission set**; the magnitude depends on the role's
  permission policies, evaluated **separately** (do not connect them). If there are
  no trust findings, say the trust appears appropriately scoped.

Do not flag the expected `sts:AssumeRole` action or normal service principals.

## Cautious phrasing (required)

- Prefer "can enable", "may allow", "could permit", "materially increases the risk
  of" over absolutes like "allows", "achieves", "full compromise".
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
- `NotAction` / `NotResource` broaden scope and need careful interpretation.
- Wildcard permissions significantly increase risk.

## Exclusions

- Do not flag standard **metadata/control-plane** reads (the read-only verbs in
  Part 1) unless combined with write, delete, or mutation actions. But a
  `Get`/`Query`/`Scan` that reads **data contents** at scale (e.g. `dynamodb:Scan`,
  `s3:GetObject`, secret reads on `Resource:"*"`) is a real exposure — judge by
  what is read, not the verb prefix.
- Do not surface findings about the **absence** of permissions — only flag what the
  policy explicitly allows that is dangerous.

## Voice

Write as a security engineer for a technical-but-not-specialist reader. Plain
language first. Avoid internal tooling terms ("deterministic", "rule engine",
"check", "mismatch") in the finished report.

## Recommendations

Actionable and specific — reference the exact action or resource pattern to fix.
Prioritize least privilege and scoping. Consolidate recommendations that share the
same root fix. Priority is LOW/MEDIUM/HIGH.

## LOW risk wording (required)

A `COMPLETE` result with no findings means *no supported high-risk pattern was
found* — not that the policy is proven safe. Phrase it that way, e.g.:

> No supported high-risk patterns were detected in this policy. This does not
> establish complete least privilege or account-level safety.

Never imply a LOW policy is audited-clean or minimal.

## Analysis limitations (always include)

Close with the relevant items naming context you could not see, e.g.:
- "Policy attachment context (user, role, group) is unknown."
- "Other identity policies, permission boundaries, and SCPs are not visible."
- "Session policies and resource-based policies are not visible."
- "Explicit Deny statements were not evaluated for net effect."
- "Trust relationships, cross-account ownership, and the role's other policies are unknown."
- "Actual resource usage and data sensitivity are not known."
