# iam-policy-analyzer-cli — Design Document

> Captured from the design discussion on 2026-07-23/27. The CLI lives in its own
> repository (`iam-policy-analyzer-cli`, not yet created); this document is
> parked here until that repo exists, then migrates with it.

## Purpose

A standalone CLI that teams embed in CI/CD pipelines (GitHub Actions, Jenkins,
CodeBuild/CodePipeline) to analyze AWS IAM policies for security risk as part
of the shift-left workflow — the enforceable counterpart to the interactive
`iam-policy-analyzer` skill. Teams may also run it locally (pre-commit,
ad-hoc scans); that is their choice, not the design driver.

## Why a CLI when the skill exists

The skill *can* run in CI (`claude -p` headless mode and
`anthropics/claude-code-action` both load skills), but an LLM run cannot be an
enforcement gate:

- **Non-deterministic** — same policy can pass one run and fail the next; a
  flaky merge gate gets bypassed or removed.
- **Credential burden** — every adopting team would need its own Anthropic
  credential just to run a lint check.
- **Cost and latency** — tokens and minutes per PR vs. milliseconds for free.
- **Reliability** — an API outage or rate limit becomes a broken pipeline.
- **Unstructured output** — CI needs exit codes and SARIF, not prose.
- **Auditability** — a security control should be a versioned, inspectable
  ruleset ("finding IAM_PASSROLE, severity CRITICAL, engine v1.2"), not "the
  model concluded."

The framing: **the LLM is the wrong layer to gate on and the right layer to
narrate with.** The deterministic engine is the credential-free gate; the LLM
is an optional non-blocking narrator on top.

## Positioning: skill and CLI are separate products

- **The skill** (this repo) is what engineers download and run locally and
  interactively — exploratory, judgment-heavy, LLM-driven. It stays as is.
- **The CLI** is its own repo with its own copy of the engine and its own
  embedded prompt assets. No shared library, no vendoring.
- Accepted cost: the two finding catalogs will drift; keep them in sync
  manually (when a finding is added to one, add it to the other in the same
  working session). Both READMEs should carry a "sibling project" note.
- Free synergy: each product references the other — the skill's report points
  to the CLI for CI enforcement; the CLI's narrative comment points to the
  skill for local deep-dives.

## Two layers, cleanly split

| Layer    | What                                                | Cost                  | Blocking? |
|----------|-----------------------------------------------------|-----------------------|-----------|
| Engine   | Deterministic findings, severity, exit codes, SARIF | Zero (no LLM)         | Optionally (opt-in) |
| Narrator | Plain-language three-lens report via `claude -p`    | Subscription (or API) | Never     |

If Claude is unreachable, rate-limited, or the token is revoked, pipelines
still gate correctly — only the prose comment is lost. A team gets full value
from the CLI alone: no Claude account, no tokens, just install and a workflow
step. The LLM layer is an upgrade, not a prerequisite.

## Enforcement model: advisory by default, opt-in gating

- **Default (no `--fail-on`): advisory.** Findings are reported (JSON/SARIF
  output, PR annotations, optional Claude comment) but exit code is 0 — the
  build never fails on findings.
- **Opt-in enforcement:** `--fail-on critical|high|medium|low` fails the run
  at that severity **and above** (the engine already emits all four levels).
  Teams choose their own bar and ratchet it over time:
  advisory → `critical` → `high` → maybe `medium`, each a one-line change
  with an audit trail in git.
- **Config file:** enforcement level also settable in `.iam-analyzer.yml`
  (`fail_on: high`) so teams codify it in-repo; the CLI flag overrides the
  config file when both are present. The GitHub Action mirrors this with a
  `fail-on:` input defaulting to advisory.
- **Carve-out:** operational failures (unreadable file, un-analyzable policy)
  keep distinct nonzero exit codes *even in advisory mode*. Advisory applies
  to findings, never to the tool failing to do its job.

## Commands

```bash
iam-analyzer scan policies/ infra/*.tf template.yaml \
    --fail-on high --format sarif -o results.sarif

iam-analyzer explain results.json                    # narrative via claude -p
iam-analyzer scan ... --baseline .iam-baseline.json  # only NEW findings fail
```

- `scan` — extract + analyze + report. Formats: `json` (engine schema),
  `sarif` (GitHub / Jenkins annotations), `markdown`.
- `explain` — takes engine JSON, produces the per-policy narrative using a
  prompt adapted from the skill's report structure (three lenses, cautious
  phrasing, limitations section), embedded in the CLI repo.
- `--baseline` — suppress known findings so only new ones gate; essential for
  adopting the tool on a repo with legacy findings without blocking every PR
  on day one.

## Input formats (v1: everything the skill supports, deterministically)

- **Raw policy JSON / manifest** — engine already handles this.
- **CloudFormation** (YAML/JSON incl. short-form intrinsics) — YAML loader
  plus intrinsic-tag handling.
- **Terraform `.tf` source** — parsed with `python-hcl2` (covers `jsonencode`,
  heredoc JSON, `aws_iam_policy_document` data blocks). The skill's rule
  carries over verbatim: a policy whose load-bearing fields are unresolved is
  reported **un-analyzable, never clean**, with its own exit code/finding so
  CI surfaces it instead of green-lighting it.
- **Terraform plan JSON** (`terraform show -json plan.out`) — fully resolved
  values and the artifact CI naturally has. Recommended CI path for
  Terraform; `.tf` source parsing is the local/fallback path.

## Auth: both modes, subscription first

```bash
claude setup-token   # one-time, local → long-lived OAuth token (Pro/Max)
# store as CI secret CLAUDE_CODE_OAUTH_TOKEN
```

`explain` shells out to `claude -p` and resolves credentials in order:

1. `CLAUDE_CODE_OAUTH_TOKEN` — subscription auth, no per-token cost (default).
2. `ANTHROPIC_API_KEY` — metered; for orgs that won't share a personal token.
3. Neither → `explain` exits with a clear "no Claude credential" message;
   `scan` remains fully functional.

Subscription caveats: CI runs share the owner's personal 5-hour/weekly usage
windows, and the token is tied to one person — fine for internal repos; a
client pipeline should bring its own API key.

## CI integration

**GitHub Actions** (composite `action.yml` shipped in the repo):

```yaml
- uses: Osias-Cloud-Security/iam-policy-analyzer-cli@v1
  with:
    paths: infra/
    fail-on: high          # omit for advisory (default)
    claude-comment: true   # optional narrative PR comment
  env:
    CLAUDE_CODE_OAUTH_TOKEN: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
```

Under the hood: `scan` → `upload-sarif` (inline PR annotations) → if enabled
and credentialed, `explain` → sticky PR comment (updated in place on new
pushes, not stacked).

**Jenkins:** `sh 'iam-analyzer scan ... --format sarif'` + Warnings NG plugin;
exit code fails the stage.

**CodeBuild/CodePipeline:** a `buildspec` phase before the CodeDeploy stage
(CodeDeploy itself doesn't run checks); nonzero exit stops the pipeline.

## Repository shape

```
iam-policy-analyzer-cli/
├── src/iam_analyzer/
│   ├── engine/            # analyzer core (CLI's own copy) + finding catalog
│   ├── extractors/        # json.py, cloudformation.py, hcl.py, tfplan.py
│   ├── reporters/         # json.py, sarif.py, markdown.py
│   ├── llm/               # claude -p shell-out + embedded report prompt
│   └── cli.py
├── action.yml             # composite GitHub Action
├── docs/ci/               # jenkins.md, codebuild.md
├── tests/                 # engine + extractor + exit-code tests
└── pyproject.toml         # pipx/uvx installable; stdlib + python-hcl2 + pyyaml
```

## Build order

1. Repo scaffold + engine copy + `scan` for JSON inputs + `--fail-on`
   (advisory default) + SARIF — a working CI gate on day one.
2. CloudFormation + Terraform plan JSON extractors.
3. `.tf` source extractor with the un-analyzable rule.
4. `explain` + dual auth.
5. Composite GitHub Action with sticky PR comment; Jenkins/CodeBuild docs.
6. `--baseline` mode.

Each step ships something usable on its own.

## Decision log

| Date       | Decision |
|------------|----------|
| 2026-07-23 | CLI gets its own repo; skill stays as is — fully separate products |
| 2026-07-23 | v1 inputs: everything the skill supports (JSON, CloudFormation, Terraform) |
| 2026-07-23 | LLM layer ships in v1: `explain` + non-blocking PR comment |
| 2026-07-23 | Auth supports both subscription (`CLAUDE_CODE_OAUTH_TOKEN`) and API key; subscription first |
| 2026-07-27 | Advisory by default; enforcement opt-in via `--fail-on` severity threshold |
| 2026-07-27 | Rationale settled: skills can run in CI, but LLM runs can't be gates — engine gates, LLM narrates |
