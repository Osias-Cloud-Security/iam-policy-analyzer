# Policy Extraction

How to find every IAM **policy document** in an input and turn each into standard
IAM-policy JSON the engine can score. The engine only consumes JSON; extraction
is your job. The unit is the whole policy document (its `Version` + the entire
`Statement` array). Review each one independently — never combine or roll up.

## Output of this step: a manifest

Build a JSON array, one element per policy document found:

```json
[
  { "source": "roles.tf: aws_iam_policy.ci_deploy", "policy": { "Version": "2012-10-17", "Statement": [ ... ] } },
  { "source": "roles.tf: aws_iam_role.app.assume_role_policy", "policy": { ... } }
]
```

- `source` — a human-readable label: file plus the resource/field it came from.
  This is how each result is identified in the report. Make it specific.
- `policy` — the extracted policy document, as a JSON object (preferred) or a
  JSON string.

Pipe the manifest to the engine: `echo "$MANIFEST" | python3 scripts/analyze_policy.py`.

## Golden rules

- **Never *silently* drop or over-claim a policy.** Both failure modes are bad: a
  silently omitted policy reads as "nothing to see," and a partially-extracted one
  presented as complete reads as "analyzed and clean." Whatever you do, make the
  state explicit (see "Unresolved values" below for the decision rule).
- **Never fabricate.** Extract only what the source actually states — never guess
  or reconstruct a missing `Action`, `Resource`, `Principal`, or `Condition`.
- **One document = one manifest entry.** Do not split a document's statements
  into separate entries, and do not merge multiple documents into one.
- **Identity vs trust is automatic.** Extract every policy faithfully — including
  role **trust policies** (`assume_role_policy` / `AssumeRolePolicyDocument`).
  The engine classifies each document by the presence of a `Principal` and routes
  it to the right analyzer; you do not need to label the type. Just make sure a
  trust policy's `Principal` and `Condition` survive extraction intact, since
  that is where its entire risk lives.

## Raw JSON

- A single policy object → one entry.
- Several policy objects, or a JSON array of them → one entry each.
- Multiple `.json` files → one entry per file (you can also just pass the files
  as arguments instead of building a manifest).

## Terraform (any `.tf` file)

IAM policies appear in any `.tf` file (not just one named `iam.tf`), in several
forms. Scan all provided Terraform for:

- **`jsonencode({ ... })`** on a `policy`, `assume_role_policy`, or
  `inline_policy.policy` argument — convert the HCL object to JSON. Common on
  `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_role.assume_role_policy`,
  `aws_iam_user_policy`, `aws_iam_group_policy`.
- **Heredoc** (`policy = <<-EOF ... EOF`) — usually literal JSON; use it directly.
- **`data "aws_iam_policy_document" "x" { statement { ... } }`** — this is **not
  JSON**. Translate each `statement` block into a policy statement:
  `effect` → `Effect`, `actions` → `Action`, `not_actions` → `NotAction`,
  `resources` → `Resource`, `not_resources` → `NotResource`, `condition` →
  `Condition`, `sid` → `Sid`. Wrap the statements in
  `{"Version": "2012-10-17", "Statement": [ ... ]}`. Label the source with the
  data source name, and also note any resource that references it (e.g.
  `aws_iam_policy.x uses data.aws_iam_policy_document.y`).
- **File references** (`policy = file("${path.module}/p.json")`) — read and
  inline that file's JSON if it is available; otherwise mark it unresolved.

## CloudFormation (JSON or YAML)

- `AWS::IAM::ManagedPolicy` and `AWS::IAM::Policy` → the `PolicyDocument`.
- `AWS::IAM::Role` → `AssumeRolePolicyDocument`, plus each `Policies[].PolicyDocument`.
- `AWS::IAM::User` / `AWS::IAM::Group` → each inline `Policies[].PolicyDocument`.
- Convert YAML to JSON. CloudFormation intrinsics (`!Ref`, `!Sub`, `!GetAtt`,
  `Fn::*`) cannot be resolved statically — keep the literal action/resource
  structure and treat unresolved values per below.

## Supported sources

In scope are the three ways engineers author IAM policies as literal documents:
**raw JSON**, **Terraform** (any `.tf` or `.tf.json`), and **CloudFormation**
(JSON or YAML). SAM templates are CloudFormation — handle them via the CFN path.

CDK, Pulumi, and cdktf author policies as *imperative code* (`role.addToPolicy`,
`grantRead`), not as policy documents — those are **not** parsed directly.
**Synthesize first** (`cdk synth` → CloudFormation, `cdktf synth` → Terraform/
JSON), then point the skill at the generated template.

## Unresolved values (variables, interpolations, intrinsics)

When a value is a reference you can't see (`var.x`, `local.y`, `${...}`, `!Ref`,
`!Sub`, an unread `file(...)`), **what to do depends on *which* field it is.**
First always **try to resolve it** from the inputs you have — look for the
`local`/`variable` definition or `*.tfvars` in the provided files and substitute.
A name like `local.scanner_role_wildcard` often resolves to a concrete (and
revealing) ARN, and its real scope changes severity materially. If it still can't
be resolved, apply this rule:

**Load-bearing fields — `Action`, `Effect`, and (for trust policies) `Principal`.**
If any of these is unresolved, the analysis has no foundation: **do not analyze
that policy and do not feed it to the engine.** An unresolved `Action` passed to
the engine matches no rule and reads as **LOW / clean** — a dangerous false
negative. Instead, surface it explicitly: *"Could not analyze `<source>` — its
`<field>` is an unresolved reference (`<the reference>`)."* Tell the user how to
provide a resolved version — e.g. `terraform plan` / `terraform show -json`, or
paste the rendered policy JSON. Never guess the missing field.

**Non-load-bearing fields — `Resource` and most `Condition` values.** The actions
are concrete, so the **core analysis still holds**: the action namespace alone
tells you the targeted service and capability (`iam:PutRolePolicy` → manages IAM
principals; `s3:GetObject` → S3 data). Extract the statement with its real
actions, do **not** invent a `Resource` or assume `"*"` — keep the unresolved
reference as its literal string (e.g. leave `Resource: "${var.bucket}"` in place)
so the statement stays well-formed; do not drop the `Resource` key (a statement
with no `Resource`/`NotResource` is rejected as malformed). Note in Analysis
Limitations that the resource scope was unresolved — *breadth/severity* is
uncertain but the capabilities stand. Don't drop it.

The guiding principle: never let an un-analyzable policy read as clean, and never
throw away a policy whose risk its concrete actions already determine.
