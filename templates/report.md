# IAM Policy Security Assessment

> One assessment block per policy document, repeated for each. Policies are
> reviewed **independently** — no combined or aggregate verdict across them.
> If a policy could not be fully extracted, say so in its Analysis Limitations.

---

## Policy: {source label — e.g. `roles.tf: aws_iam_policy.ci_deploy`}

**Type:** {identity | trust} &nbsp;·&nbsp; **Risk level (this policy only):** {LOW | MEDIUM | HIGH | CRITICAL}

<!-- Only use the sections below when analysis_status is COMPLETE. Otherwise give
     no risk rating and state the reason:
     - INVALID: malformed policy AWS would reject — name each invalid_statements
       entry (index + reason) and ask the user to fix and resubmit.
     - NOT_ANALYZED: resource-based policy, out of scope. -->


> One or two sentences of plain-language summary: what this policy is broadly
> able to do (identity) or who it lets assume the role (trust). No jargon.

<!-- TRUST POLICIES: keep all three sections; drive them from the Principal/Condition
     per analysis.md Part 2 ("Trust policies"). Blast Radius is a conditional note. -->


## Least Privilege

> Scope problems only — where actions/resources exceed the minimum necessary.
> Omit the section body and write "No least-privilege concerns identified." if empty.

- **{Short title}** — _{SEVERITY}_
  {Plain-language explanation. One technical sentence naming the specific action
  or resource pattern.}

## Escalation Paths

> Mechanism only — how permissions could be chained to gain higher privilege.
> Include only when the policy plainly enables it. "No escalation paths identified."
> if empty.

- **{Short title}** — _{SEVERITY}_
  {Plain-language explanation of the specific capability — not a blanket claim.
  One sentence naming the permission combination that enables it.}

## Blast Radius

> Impact only — realistic damage if these credentials were stolen. Conservative,
> scoped to what the policy directly enables. "Impact appears limited." if minimal.

- **{Short title}** — _{SEVERITY}_
  {Plain-language outcome. One sentence naming the permissions driving the impact.}

## Recommendations

| Priority | Action | Reason |
|----------|--------|--------|
| {LOW/MEDIUM/HIGH} | {Specific fix referencing the exact action/resource} | {Grounded in a named AWS best practice or CIS control} |

## Analysis Limitations

This assessment is based solely on this policy document. List the relevant items
from analysis.md Part 2 ("Analysis limitations"), e.g.:

- Policy attachment context (user, role, group) is unknown.
- Other identity policies, permission boundaries, SCPs, and session policies are not visible.
- {If explicit_deny_present: Explicit Deny statements were not evaluated for net effect.}
- {If extraction was partial: name the unresolved values and note the assessment is partial.}

---

_Repeat the block above for each policy document. Do not add an overall or
aggregate verdict across policies. Follow analysis.md Part 2 for cautious phrasing
and voice._
