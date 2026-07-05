# IAM Policy Analyzer

**Static AWS IAM policy security analysis. No account access required.**

A Claude [Agent Skill](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview) that analyzes one or more AWS IAM policies and produces a plain-language security assessment per policy: least-privilege violations, privilege-escalation paths, and blast radius, with prioritized recommendations.

It pairs a **deterministic rule engine** with **model-driven write-up guidance** (clear, cautious phrasing). Everything is based solely on the policy text; it never assumes attachment context, SCPs, permission boundaries, or runtime usage.

> **Claude Code only.** This is a skill for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and the Claude apps. It is not a standalone tool, and it is not compatible with Cursor, Copilot, Windsurf, or other AI coding tools.

---

## The Problem

IAM policies are easy to write and hard to read. A lone `Action: "*"`, an `iam:PassRole` paired with the right compute action, or a trust policy missing a confused-deputy guard can hand over far more than intended, and none of it is obvious from a glance at the JSON.

Reviewing policies by hand is slow, inconsistent, and easy to get wrong. Most linters either drown you in noise or miss the chained risks (escalation paths, blast radius) that actually matter.

## The Solution

Point the skill at whatever you have (pasted JSON, Terraform, CloudFormation) and it extracts every policy document and scores each one independently. A deterministic engine supplies reproducible findings for the supported high-risk patterns; Claude turns them into a careful, prioritized report.

```
iam-policy-analyzer/
  SKILL.md                       # entry point: the analysis workflow + when to use it
  scripts/analyze_policy.py      # deterministic rule engine (Python stdlib only, no dependencies)
  reference/extraction.md        # how to pull policies from JSON / Terraform / CloudFormation
  reference/analysis.md          # every finding id + severity logic, and how to write the report
  templates/report.md            # output skeleton (one block per policy)
```

You get a per-policy risk level (LOW / MEDIUM / HIGH / CRITICAL) and specific fixes, without false positives on routine read-only access. See [`reference/analysis.md`](reference/analysis.md) for the full list of findings and severity rules.

---

## Installation

```bash
git clone https://github.com/osias-cloud-security/iam-policy-analyzer.git ~/.claude/skills/iam-policy-analyzer
```

This installs the skill globally; it's available in every project you open with Claude Code.

### Add to a specific project only

If you prefer to scope the skill to a single project instead of installing it globally:

```bash
cd your-project
mkdir -p .claude/skills
git clone https://github.com/osias-cloud-security/iam-policy-analyzer.git .claude/skills/iam-policy-analyzer
```

Project-level skills live in `.claude/skills/` and are only active in that project.

## Quick Start

Open Claude Code in your project and just ask. Paste a policy inline, or point it at a file (a Terraform `.tf`, a CloudFormation/SAM template, a `.json` policy):

```
Analyze the IAM policies in roles.tf for least-privilege and escalation risks.
```

Claude recognizes the task from the skill's description, runs it, and returns a per-policy security report. No manual setup required.

### Updating

```bash
cd ~/.claude/skills/iam-policy-analyzer && git pull
```

---

## How It Works

The skill follows three principles:

**Deterministic first.** A Python rule engine (stdlib only, no dependencies) classifies each document as an identity or trust policy and flags the known-dangerous patterns. Claude never invents findings the policy text doesn't support.

**One policy, one verdict.** Every policy document is scored independently through three lenses: least privilege, escalation paths, and blast radius. When several are present, they are never combined or rolled up into a single verdict.

**Cautious by default.** Findings are phrased conservatively, and every report names the context it could not see: attachments, SCPs, permission boundaries, runtime usage, etc.

---

## Scope

Strictly IAM **identity** policies (managed or inline) and role **trust** policies. Service resource-based policies (S3 bucket, KMS key, SQS, SNS, Lambda, DynamoDB) are **out of scope** and not scored. Service control policies (SCPs) and live account auditing are also out of scope.

## Disclaimer

The report is **AI-generated and can miss things**: it is a first-pass review, not an authoritative audit. Always have a qualified engineer review any changes before applying them.

## Maintenance

The engine (`scripts/analyze_policy.py`) is the behavioral source of truth. When you change it, update the reference docs (`reference/analysis.md`, `reference/extraction.md`) to match, so the documented findings, severities, and report guidance stay in sync with what the engine actually does.

## License

[MIT](LICENSE).

---

Built by Osias Cloud Security.

*Know your posture. Close your gaps.*
