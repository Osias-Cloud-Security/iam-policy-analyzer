#!/usr/bin/env python3
"""Deterministic AWS IAM policy rule engine for the iam-policy-analyzer skill.

Pure Python standard library — no third-party dependencies.

Analyzes one or more AWS IAM policy documents (JSON) and prints a JSON object:

    {"policies": [
        {"source": "...", "valid": true, "parse_error": null,
         "analysis_status": "COMPLETE|INVALID|NOT_ANALYZED",
         "findings": [...], "summary": {"risk_level": "...|null"},
         "explicit_deny_present": false, "effective_permissions_calculated": false,
         "invalid_statements": [...]},  # present only when status is INVALID
        ...
    ]}

`analysis_status` is separate from risk:
  - COMPLETE     — every statement analyzable; risk_level set.
  - INVALID      — malformed document or a schema-violating statement
  - NOT_ANALYZED — out-of-scope resource-based policy; risk_level null.

Unit of analysis is the whole policy DOCUMENT (its Version plus the entire
Statement array, however many statement blocks / Sids it contains). Each
document is evaluated independently and gets its own findings and its own
risk_level. There is NO combination or roll-up ACROSS documents.

The engine only consumes JSON policy documents. Extracting policies from other
sources (Terraform jsonencode/heredoc/aws_iam_policy_document, CloudFormation,
etc.) is the skill's job: the agent extracts each policy, builds a manifest, and
feeds it here — see ../reference/extraction.md.

Accepted inputs (any of):
  - One or more files, each containing a single policy document, a JSON array
    of policy documents, or a manifest (see below).
  - stdin containing the same.
  - A manifest: a JSON array of objects {"source": "label", "policy": <policy>},
    where <policy> is either a policy document object or a JSON string. This is
    the primary agent -> engine interface; "source" labels each result.

Usage:
    python3 analyze_policy.py policy.json
    python3 analyze_policy.py policy1.json policy2.json
    cat manifest.json | python3 analyze_policy.py
"""

import argparse
import fnmatch
import json
import re
import sys
from typing import Any, Dict, List, Set, Tuple

# Process exit codes. Note: a per-policy `valid: false` (malformed JSON content,
# no Statement, etc.) is a legitimate analysis RESULT carried in the output JSON,
# NOT a script failure — so it does not change the exit code. Non-zero is reserved
# for the script being unable to do its job at all.
EXIT_OK = 0          # analysis completed for every input; results emitted
EXIT_NO_INPUT = 1    # nothing to analyze (empty stdin / no policy provided)
EXIT_READ_ERROR = 2  # at least one named file could not be read

READ_ONLY_PREFIXES = ("describe", "get", "list", "lookup", "view")

SENSITIVE_WILDCARD_SERVICES = {
    "iam", "kms", "secretsmanager", "ssm", "s3", "ec2",
    "lambda", "cloudformation", "organizations", "sts",
}

POLICY_MUTATION_ACTIONS = {
    "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachrolepolicy", "iam:attachuserpolicy", "iam:attachgrouppolicy",
    "iam:putrolepolicy", "iam:putuserpolicy", "iam:putgrouppolicy",
}

PASSROLE_ACTION = "iam:passrole"

ASSUME_ROLE_ACTIONS = {
    "sts:assumerole", "sts:assumerolewithsaml", "sts:assumerolewithwebidentity",
}

SECRETS_ACTIONS = {
    "secretsmanager:getsecretvalue", "ssm:getparameter", "ssm:getparameters",
    "ssm:getparametersbypath", "kms:decrypt",
}

# Actions that launch/configure a compute resource which then runs code under a
# *passed* role. Combined with iam:PassRole this is a privilege-escalation
# primitive. This list is representative, not exhaustive — the agent should treat
# any "create/configure a resource that runs with a passed role" action (e.g.
# Batch, CodeBuild, EMR) as the same class via judgment.
COMPUTE_ROLE_INJECTION_ACTIONS = {
    "lambda:createfunction", "lambda:updatefunctionconfiguration",
    "ec2:runinstances", "cloudformation:createstack",
    "cloudformation:updatestack", "glue:createjob",
    "ecs:registertaskdefinition",
    "sagemaker:createtrainingjob", "sagemaker:createnotebookinstance",
    "sagemaker:createprocessingjob",
}

# --- Trust-policy (Principal-aware) analysis ------------------------------
# A trust policy answers "who may assume this role". The risk lives in the
# Principal element and the Condition scoping it — not in Action/Resource
# (the Action is almost always sts:AssumeRole-family and is expected).
# Condition-key sets below are drawn from the AWS global condition context
# keys reference and the confused-deputy guidance.

# The trust-policy condition-key sets (scoping tiers + confused-deputy guards)
# are defined together near the effectiveness classifier below.

ASSUME_WEB_IDENTITY_ACTION = "sts:assumerolewithwebidentity"
ASSUME_SAML_ACTION = "sts:assumerolewithsaml"


def _to_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_str(value: Any) -> str:
    return str(value).strip()


def _normalize_actions(statement: Dict[str, Any]) -> List[str]:
    return [_normalize_str(a).lower() for a in _to_list(statement.get("Action")) if _normalize_str(a)]


def _normalize_not_actions(statement: Dict[str, Any]) -> List[str]:
    return [_normalize_str(a).lower() for a in _to_list(statement.get("NotAction")) if _normalize_str(a)]


def _normalize_resources(statement: Dict[str, Any]) -> List[str]:
    return [_normalize_str(r) for r in _to_list(statement.get("Resource")) if _normalize_str(r)]


def _normalize_not_resources(statement: Dict[str, Any]) -> List[str]:
    return [_normalize_str(r) for r in _to_list(statement.get("NotResource")) if _normalize_str(r)]


def _has_conditions(statement: Dict[str, Any]) -> bool:
    cond = statement.get("Condition")
    return isinstance(cond, dict) and len(cond) > 0


def _is_allow(statement: Dict[str, Any]) -> bool:
    return str(statement.get("Effect", "")).strip().lower() == "allow"


def _is_deny(statement: Dict[str, Any]) -> bool:
    return str(statement.get("Effect", "")).strip().lower() == "deny"


def _action_matches(action: str, pattern: str) -> bool:
    return fnmatch.fnmatch(action.lower(), pattern.lower())


def _contains_action(actions: List[str], target: str) -> bool:
    target = target.lower()
    return any(_action_matches(action, target) for action in actions)


def _contains_any_action(actions: List[str], targets: Set[str]) -> bool:
    return any(_contains_action(actions, target) for target in targets)


def _contains_service_wildcard(actions: List[str], service: str) -> bool:
    return any(action == f"{service}:*" or action == "*" for action in actions)


def _is_full_admin(actions: List[str], resources: List[str]) -> bool:
    return any(action == "*" for action in actions) and any(resource == "*" for resource in resources)


def _has_wildcard_resource(resources: List[str]) -> bool:
    return any(resource == "*" for resource in resources)


def _looks_read_only(action: str) -> bool:
    if ":" not in action:
        return False
    _, verb = action.split(":", 1)
    return any(verb.startswith(prefix) for prefix in READ_ONLY_PREFIXES)


def _all_actions_read_only(actions: List[str]) -> bool:
    # `*` is non-read-only; treating it as read-only would vacuously pass the
    # WRITE_ON_ALL_RESOURCES / WILDCARD_ACTIONS_AND_RESOURCES guards.
    if not actions or any(action == "*" for action in actions):
        return False
    return all(_looks_read_only(action) for action in actions)


def _statement_scope_note(statement: Dict[str, Any]) -> str:
    parts = []
    if _has_conditions(statement):
        parts.append("statement includes conditions")
    if statement.get("NotAction") is not None:
        parts.append("uses NotAction")
    if statement.get("NotResource") is not None:
        parts.append("uses NotResource")
    return "; ".join(parts)


# Finding category — separates genuine defects from powerful-but-scoped
# capabilities so a tightly-scoped grant is not mislabeled a vulnerability.
#   SECURITY_RISK        — a broad/unsafe grant that is a defect on its own
#   BROAD_PERMISSION     — wildcard breadth (service-wide / bulk data)
#   PRIVILEGE_ESCALATION — can be chained to gain higher privilege
#   SENSITIVE_CAPABILITY — a sensitive but scoped capability (review, not defect)
_SECURITY_RISK_IDS = {
    "FULL_ADMIN", "WILDCARD_ACTIONS_AND_RESOURCES", "WRITE_ON_ALL_RESOURCES",
    "ALLOW_NOTACTION", "ALLOW_NOTRESOURCE",
    "TRUST_PRINCIPAL_WILDCARD", "TRUST_ACCOUNT_ROOT", "TRUST_NOTPRINCIPAL",
}
_BROAD_PERMISSION_IDS = {"BROAD_S3_DATA_ACCESS"}
_PRIVILEGE_ESCALATION_IDS = {
    "IAM_PASSROLE", "IAM_POLICY_MUTATION", "COMPUTE_ROLE_INJECTION",
    "TRUST_CROSS_ACCOUNT_NO_EXTERNALID", "TRUST_FEDERATED_UNSCOPED", "TRUST_SAML_UNSCOPED",
}
_SENSITIVE_CAPABILITY_IDS = {"SENSITIVE_DATA_ACCESS"}


def _category_for(finding_id: str, severity: str) -> str:
    if finding_id.startswith("SERVICE_WILDCARD_"):
        return "BROAD_PERMISSION"
    if finding_id in _SECURITY_RISK_IDS:
        return "SECURITY_RISK"
    if finding_id in _BROAD_PERMISSION_IDS:
        return "BROAD_PERMISSION"
    if finding_id in _PRIVILEGE_ESCALATION_IDS:
        return "PRIVILEGE_ESCALATION"
    if finding_id in _SENSITIVE_CAPABILITY_IDS:
        return "SENSITIVE_CAPABILITY"
    # Scope-dependent: a scoped grant (MEDIUM) is a capability, not a defect.
    if finding_id == "STS_ASSUME_ROLE":
        return "PRIVILEGE_ESCALATION" if severity == "HIGH" else "SENSITIVE_CAPABILITY"
    if finding_id == "COMPUTE_CONTROL":
        return "BROAD_PERMISSION" if severity == "HIGH" else "SENSITIVE_CAPABILITY"
    return "REVIEW_REQUIRED"


def _make_finding(finding_id: str, title: str, severity: str, description: str, statement_index: int) -> Dict[str, Any]:
    return {
        "id": finding_id,
        "category": _category_for(finding_id, severity),
        "title": title,
        "severity": severity,
        "description": description,
        "statement_index": statement_index,
    }


# Statement validation (P1). A statement the engine cannot reason about must be
# surfaced, never silently skipped — otherwise a malformed policy reads as a
# clean LOW. `_DENY` marks a Deny statement: understood and intentionally not
# acted on (not a defect, not a skip).
_DENY = object()


def _valid_str_or_list(value: Any) -> bool:
    """True if value is the AWS-valid shape for Action/Resource: a string or a
    list of strings."""
    if isinstance(value, str):
        return True
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _statement_problem(raw_stmt: Any, is_trust: bool) -> Any:
    """Returns None if the statement is analyzable, `_DENY` if it is a Deny
    (skip cleanly), or a human-readable reason string if it is malformed."""
    if not isinstance(raw_stmt, dict):
        return "statement is not a JSON object"

    effect = raw_stmt.get("Effect")
    if effect is None:
        return "statement has no Effect"
    if not isinstance(effect, str) or effect.strip().lower() not in ("allow", "deny"):
        return f"statement has an invalid Effect ({effect!r})"
    if effect.strip().lower() == "deny":
        return _DENY

    for key in ("Action", "NotAction"):
        if key in raw_stmt and not _valid_str_or_list(raw_stmt[key]):
            return f"{key} has an invalid type"
    if "Action" not in raw_stmt and "NotAction" not in raw_stmt:
        return "statement has neither Action nor NotAction"
    if "Condition" in raw_stmt and not isinstance(raw_stmt["Condition"], dict):
        return "Condition has an invalid type"

    if is_trust:
        if "Principal" in raw_stmt and not isinstance(raw_stmt["Principal"], (str, dict)):
            return "Principal has an invalid type"
        if "Principal" not in raw_stmt and "NotPrincipal" not in raw_stmt:
            return "trust statement has neither Principal nor NotPrincipal"
    else:
        for key in ("Resource", "NotResource"):
            if key in raw_stmt and not _valid_str_or_list(raw_stmt[key]):
                return f"{key} has an invalid type"
        if "Resource" not in raw_stmt and "NotResource" not in raw_stmt:
            return "statement has neither Resource nor NotResource"
    return None


def _validate_statements(statements: List[Any], is_trust: bool) -> List[Dict[str, Any]]:
    """Returns [{statement_index, reason}] for every malformed statement. An
    empty list means every statement is structurally analyzable. A malformed
    statement makes the WHOLE policy invalid — AWS rejects such a policy on
    submission, so the engine must not score a subset of it."""
    invalid: List[Dict[str, Any]] = []
    for idx, raw in enumerate(statements):
        problem = _statement_problem(raw, is_trust)
        if problem is _DENY or problem is None:
            continue
        invalid.append({"statement_index": idx, "reason": problem})
    return invalid


def _invalid_document(message: str) -> Dict[str, Any]:
    """Result for a document the engine cannot parse/use at all. risk_level is
    null (an unanalyzable document has no risk score), status INVALID."""
    return {
        "valid": False,
        "parse_error": message,
        "analysis_status": "INVALID",
        "findings": [],
        "summary": {"risk_level": None},
    }


def _invalid_statements_result(invalid: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Result when one or more statements are malformed: stop and report which,
    rather than scoring the well-formed remainder."""
    detail = "; ".join(f"statement[{e['statement_index']}]: {e['reason']}" for e in invalid)
    result = _invalid_document(f"Policy cannot be analyzed — {detail}.")
    result["invalid_statements"] = invalid
    return result


def analyze_iam_policy(policy_text: str) -> Dict[str, Any]:
    try:
        policy = json.loads(policy_text)
    except Exception as exc:
        return _invalid_document(f"Invalid JSON: {exc}")

    if not isinstance(policy, dict):
        return _invalid_document("Policy must be a JSON object.")

    statements = _to_list(policy.get("Statement"))
    if not statements:
        return _invalid_document("Policy contains no Statement entries.")

    invalid_statements = _validate_statements(statements, is_trust=False)
    if invalid_statements:
        return _invalid_statements_result(invalid_statements)

    findings: List[Dict[str, Any]] = []
    explicit_deny_present = False
    # Policy-level tracking so PassRole + compute provisioning split across
    # separate statements is still caught (IAM unions statements in a policy).
    policy_has_passrole = False
    policy_has_compute_injection = False
    same_statement_injection = False

    for idx, raw_stmt in enumerate(statements):
        if _is_deny(raw_stmt):
            explicit_deny_present = True
            continue

        actions = _normalize_actions(raw_stmt)
        not_actions = _normalize_not_actions(raw_stmt)
        resources = _normalize_resources(raw_stmt)
        not_resources = _normalize_not_resources(raw_stmt)
        scope_note = _statement_scope_note(raw_stmt)

        if not_actions:
            desc = ("This allow statement uses NotAction, which broadens permission scope "
                    "in ways that are harder to reason about safely.")
            if scope_note:
                desc += f" Additional context: {scope_note}."
            findings.append(_make_finding("ALLOW_NOTACTION", "Allow statement uses NotAction", "HIGH", desc, idx))

        if _is_full_admin(actions, resources):
            findings.append(_make_finding(
                "FULL_ADMIN",
                'Full administrative access ("Action": "*" and "Resource": "*")',
                "CRITICAL",
                "This statement grants effectively unrestricted access across AWS resources.",
                idx,
            ))

        for svc in SENSITIVE_WILDCARD_SERVICES:
            if _contains_service_wildcard(actions, svc):
                findings.append(_make_finding(
                    f"SERVICE_WILDCARD_{svc.upper()}",
                    f"Broad wildcard access to sensitive service: {svc}:*",
                    "HIGH",
                    f"This statement grants broad access to the {svc} service, increasing security risk and deviating from least privilege.",
                    idx,
                ))

        if _contains_action(actions, PASSROLE_ACTION):
            severity = "CRITICAL" if _has_wildcard_resource(resources) else "HIGH"
            desc = "This statement allows iam:PassRole, which is a common privilege escalation primitive when combined with services that can assume roles."
            if _has_wildcard_resource(resources):
                desc += ' It is broadly scoped to Resource "*".'
            findings.append(_make_finding("IAM_PASSROLE", "iam:PassRole is allowed", severity, desc, idx))

        if _contains_any_action(actions, ASSUME_ROLE_ACTIONS):
            wildcard = _has_wildcard_resource(resources)
            severity = "HIGH" if wildcard else "MEDIUM"
            title = "Role assumption allowed on any role" if wildcard else "Role assumption is allowed"
            if wildcard:
                desc = "This statement allows assuming any role (Resource \"*\"), which may enable lateral movement or access expansion depending on target roles."
            else:
                desc = "This statement allows assuming the named role(s); whether this enables escalation depends on the target role's permissions."
            findings.append(_make_finding("STS_ASSUME_ROLE", title, severity, desc, idx))

        if _contains_any_action(actions, POLICY_MUTATION_ACTIONS):
            critical = _contains_action(actions, "iam:createpolicyversion") or _contains_action(actions, "iam:setdefaultpolicyversion")
            severity = "CRITICAL" if critical else "HIGH"
            desc = ("This statement allows IAM policy modification actions, which can be used "
                    "to expand privileges or attach broader permissions.")
            findings.append(_make_finding("IAM_POLICY_MUTATION", "IAM policy mutation actions are allowed", severity, desc, idx))

        if _contains_any_action(actions, SECRETS_ACTIONS):
            severity = "HIGH" if _has_wildcard_resource(resources) else "MEDIUM"
            desc = ("This statement allows access to secrets, parameters, or decryption operations, "
                    "which may expose sensitive data.")
            findings.append(_make_finding("SENSITIVE_DATA_ACCESS", "Sensitive data access is allowed", severity, desc, idx))

        has_compute_injection = _contains_any_action(actions, COMPUTE_ROLE_INJECTION_ACTIONS)
        has_passrole = _contains_action(actions, PASSROLE_ACTION)
        policy_has_passrole = policy_has_passrole or has_passrole
        policy_has_compute_injection = policy_has_compute_injection or has_compute_injection
        if has_compute_injection and has_passrole:
            same_statement_injection = True
            findings.append(_make_finding(
                "COMPUTE_ROLE_INJECTION",
                "Compute provisioning combined with iam:PassRole",
                "CRITICAL",
                "This statement combines service creation or configuration permissions with iam:PassRole, which can enable privilege escalation through service role assignment.",
                idx,
            ))
        elif has_compute_injection:
            wildcard = _has_wildcard_resource(resources)
            severity = "HIGH" if wildcard else "MEDIUM"
            title = ("Broad compute or infrastructure provisioning allowed" if wildcard
                     else "Compute or infrastructure provisioning is allowed")
            findings.append(_make_finding(
                "COMPUTE_CONTROL",
                title,
                severity,
                "This statement allows creation or reconfiguration of compute or infrastructure services, which can materially increase blast radius.",
                idx,
            ))

        # Broad S3 data access: the statement grants an S3 object read/write/delete
        # action — named exactly (s3:GetObject) OR via a wildcard that covers it
        # (s3:Get*, s3:*, *). Coverage is tested with _action_matches(target, action)
        # = fnmatch(target, action): the POLICY action is the glob (pattern) and the
        # concrete object action is the candidate it may grant. Matching the other
        # direction (an action against an "s3:*" pattern) would wrongly flag
        # metadata-only reads like s3:ListAllMyBuckets, so we deliberately avoid it.
        grants_s3_object_data = any(
            _action_matches(target, a)
            for a in actions
            for target in ("s3:getobject", "s3:putobject", "s3:deleteobject")
        )
        if grants_s3_object_data and _has_wildcard_resource(resources):
            findings.append(_make_finding(
                "BROAD_S3_DATA_ACCESS",
                "Broad S3 data access is allowed",
                "HIGH",
                "This statement allows broad read, write, or delete access to S3 objects, which may expose or alter data at scale.",
                idx,
            ))

        if any("*" in a for a in actions) and _has_wildcard_resource(resources) and not _all_actions_read_only(actions):
            findings.append(_make_finding(
                "WILDCARD_ACTIONS_AND_RESOURCES",
                "Wildcard actions are combined with wildcard resources",
                "CRITICAL",
                "This statement combines broad actions with broad resource scope, creating substantial exposure.",
                idx,
            ))

        if _has_wildcard_resource(resources) and actions and not _all_actions_read_only(actions):
            findings.append(_make_finding(
                "WRITE_ON_ALL_RESOURCES",
                'Write-capable permissions apply to Resource "*"',
                "HIGH",
                "This statement applies write, mutation, or otherwise non-read-only permissions to all resources.",
                idx,
            ))

        if not_resources:
            findings.append(_make_finding(
                "ALLOW_NOTRESOURCE",
                "Allow statement uses NotResource",
                "HIGH",
                "This allow statement uses NotResource, which can unintentionally broaden access and is harder to validate safely.",
                idx,
            ))

    # Cross-statement escalation: PassRole and a compute-provisioning action in
    # SEPARATE statements still combine, because IAM unions a policy's statements.
    # statement_index -1 denotes a policy-level (cross-statement) finding.
    if policy_has_passrole and policy_has_compute_injection and not same_statement_injection:
        findings.append(_make_finding(
            "COMPUTE_ROLE_INJECTION",
            "iam:PassRole and compute provisioning combined across statements",
            "CRITICAL",
            "Separate statements grant iam:PassRole and a compute-provisioning action; because a policy's statements are additive, together they can enable privilege escalation by running code under a passed role.",
            -1,
        ))

    findings = _dedupe_findings(findings)
    findings = _consolidate_full_admin(findings)
    return {
        "valid": True,
        "parse_error": None,
        "analysis_status": "COMPLETE",
        "findings": findings,
        "summary": {"risk_level": _derive_overall_risk(findings)},
        "explicit_deny_present": explicit_deny_present,
        "effective_permissions_calculated": False,
    }


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, int]] = set()
    for finding in findings:
        key = (finding["id"], finding["statement_index"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


# Breadth findings that FULL_ADMIN already covers within the same statement —
# `Action:"*"` + `Resource:"*"` grants all of these, so they are noise.
_COVERED_BY_FULL_ADMIN = {
    "BROAD_S3_DATA_ACCESS", "WILDCARD_ACTIONS_AND_RESOURCES", "WRITE_ON_ALL_RESOURCES",
}


def _consolidate_full_admin(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """When FULL_ADMIN fires for a statement, drop the breadth findings it
    already covers at that same statement_index and fold the affected services
    into FULL_ADMIN's metadata. Escalation findings are kept (distinct risk)."""
    admin_idxs = {f["statement_index"] for f in findings if f["id"] == "FULL_ADMIN"}
    if not admin_idxs:
        return findings

    services_by_idx: Dict[int, List[str]] = {}
    kept: List[Dict[str, Any]] = []
    for f in findings:
        idx = f["statement_index"]
        if idx in admin_idxs and f["id"] != "FULL_ADMIN":
            if f["id"].startswith("SERVICE_WILDCARD_"):
                services_by_idx.setdefault(idx, []).append(f["id"][len("SERVICE_WILDCARD_"):].lower())
                continue
            if f["id"] in _COVERED_BY_FULL_ADMIN:
                continue
        kept.append(f)

    for f in kept:
        if f["id"] == "FULL_ADMIN" and services_by_idx.get(f["statement_index"]):
            f["metadata"] = {"affected_services": sorted(services_by_idx[f["statement_index"]])}
    return kept


def _derive_overall_risk(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "LOW"
    severities = {f["severity"] for f in findings}
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    return "LOW"


# --- Trust-policy helpers -------------------------------------------------

_ACCOUNT_ROOT_RE = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:root$", re.IGNORECASE)
_BARE_ACCOUNT_RE = re.compile(r"^\d{12}$")


def _condition_keys(statement: Dict[str, Any]) -> Set[str]:
    """Returns the set of lowercased context keys used in a statement's
    Condition block, across all operators (e.g. {"sts:externalid"})."""
    keys: Set[str] = set()
    cond = statement.get("Condition")
    if isinstance(cond, dict):
        for operand in cond.values():
            if isinstance(operand, dict):
                for key in operand:
                    keys.add(_normalize_str(key).lower())
    return keys


def _principal_field(statement: Dict[str, Any], key: str) -> List[str]:
    """Returns the list of values under Principal[key] (AWS, Service, Federated).
    A bare `"Principal": "*"` is reported under the AWS key as ["*"]."""
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"] if key == "AWS" else []
    if isinstance(principal, dict):
        return [_normalize_str(v) for v in _to_list(principal.get(key)) if _normalize_str(v)]
    return []


def _principal_is_wildcard(statement: Dict[str, Any]) -> bool:
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(_normalize_str(v) == "*" for v in _to_list(principal.get("AWS")))
    return False


def _is_account_principal(value: str) -> bool:
    """True for an account-root ARN or a bare 12-digit account id — both
    delegate trust to an ENTIRE account rather than a specific role/user."""
    return bool(_ACCOUNT_ROOT_RE.match(value) or _BARE_ACCOUNT_RE.match(value))


# Two INDEPENDENT axes over trust-policy Condition keys — they overlap in
# membership on purpose, because they answer different questions:
#
#   1. SCOPING TIER (PRECISE vs BROAD) — how tightly the condition narrows WHO
#      may assume, used to grade severity. PRECISE names a specific principal or
#      resource; BROAD limits to an account / org / network only.
#   2. CONFUSED-DEPUTY GUARD — the subset of keys that specifically mitigate the
#      cross-account confused-deputy problem (used only by the account-root
#      check). It deliberately spans BOTH tiers (e.g. aws:SourceArn is precise,
#      aws:PrincipalOrgID is broad), so it is an axis, not a tier.
PRECISE_SCOPING_KEYS = {"aws:principalarn", "aws:userid", "aws:username", "aws:sourcearn"}
BROAD_SCOPING_KEYS = {
    "aws:principalaccount", "aws:principalorgid", "aws:principalorgpaths",
    "sts:externalid", "aws:sourceaccount", "aws:sourceorgid", "aws:sourceorgpaths",
    "aws:multifactorauthpresent", "aws:multifactorauthage",
    "aws:sourceip", "aws:sourcevpc", "aws:sourcevpce",  # network-path scoping (STS VPC endpoint)
    "aws:federatedprovider",
}
CONFUSED_DEPUTY_GUARD_KEYS = {
    "sts:externalid",
    "aws:principalorgid", "aws:principalorgpaths",
    "aws:sourcearn", "aws:sourceaccount", "aws:sourceorgid", "aws:sourceorgpaths",
}
# Invariant: every confused-deputy guard must also be a recognized scoping key.
assert CONFUSED_DEPUTY_GUARD_KEYS <= PRECISE_SCOPING_KEYS | BROAD_SCOPING_KEYS


def _split_operator(operator: str) -> Tuple[str, bool]:
    """Reduces a condition operator to its base name and whether it actually
    NARROWS access. Returns (base, narrows). An operator does not narrow if it
    is negative (`...NotEquals`), conditional (`...IfExists`), a `ForAllValues`
    set match (vacuous-truth bypass when the key is absent), or `Null`."""
    low = _normalize_str(operator).lower()
    set_op = ""
    for prefix in ("forallvalues:", "foranyvalue:"):
        if low.startswith(prefix):
            set_op = prefix[:-1]
            low = low[len(prefix):]
            break
    if low.endswith("ifexists"):
        return low, False
    if set_op == "forallvalues":
        return low, False
    if low == "null" or "not" in low:
        return low, False
    return low, True


def _effective_conditions(statement: Dict[str, Any]) -> Dict[str, List[str]]:
    """Returns {context_key: [values]} for conditions that EFFECTIVELY narrow
    access — positive, non-IfExists, non-ForAllValues operators whose values are
    all wildcard-free. A key constrained only by a wildcard value (e.g.
    `ArnLike …::*:role/*`) or an illusory operator is treated as no constraint.
    This is what prevents a worthless condition from downgrading severity."""
    effective: Dict[str, List[str]] = {}
    cond = statement.get("Condition")
    if not isinstance(cond, dict):
        return effective
    for operator, mapping in cond.items():
        if not isinstance(mapping, dict):
            continue
        _, narrows = _split_operator(operator)
        if not narrows:
            continue
        for key, raw in mapping.items():
            values = [_normalize_str(v) for v in _to_list(raw) if _normalize_str(v)]
            if not values or any("*" in v or "?" in v for v in values):
                continue  # no values, or a wildcard value => not an exact constraint
            effective.setdefault(_normalize_str(key).lower(), []).extend(values)
    return effective


def _scope_tier(statement: Dict[str, Any]) -> str:
    """Classifies the effective scoping on a statement: 'precise' (a specific
    principal/resource is named), 'broad' (account/org/network scoping only), or
    'none' (no effective scoping)."""
    effective = _effective_conditions(statement)
    keys = set(effective)

    precise = bool(keys & (PRECISE_SCOPING_KEYS - {"aws:principalarn"}))
    if "aws:principalarn" in keys:
        # An exact PrincipalArn is only "precise" if it names a specific
        # principal — a `…:root` / account value is account-level, i.e. broad.
        if any(not _is_account_principal(v) for v in effective["aws:principalarn"]):
            precise = True
    if precise:
        return "precise"
    if (keys & BROAD_SCOPING_KEYS) or "aws:principalarn" in keys:
        return "broad"
    return "none"


def _has_effective_cd_guard(statement: Dict[str, Any]) -> bool:
    """True if a confused-deputy guard key is applied via an effective condition."""
    return bool(set(_effective_conditions(statement)) & CONFUSED_DEPUTY_GUARD_KEYS)


def _federation_subject_values(statement: Dict[str, Any]) -> List[str]:
    """All condition values bound to a federation `:sub` or `:aud` context key,
    across every operator."""
    values: List[str] = []
    cond = statement.get("Condition")
    if not isinstance(cond, dict):
        return values
    for mapping in cond.values():
        if not isinstance(mapping, dict):
            continue
        for key, raw in mapping.items():
            k = _normalize_str(key).lower()
            if k.endswith(":sub") or k.endswith(":aud"):
                values.extend(_normalize_str(v) for v in _to_list(raw) if _normalize_str(v))
    return values


def analyze_trust_policy(policy_text: str) -> Dict[str, Any]:
    """Principal-aware analysis of a role trust policy. Evaluates who may assume
    the role and how well that trust is scoped."""
    try:
        policy = json.loads(policy_text)
    except Exception as exc:
        return _invalid_document(f"Invalid JSON: {exc}")

    if not isinstance(policy, dict):
        return _invalid_document("Policy must be a JSON object.")

    statements = _to_list(policy.get("Statement"))
    if not statements:
        return _invalid_document("Policy contains no Statement entries.")

    invalid_statements = _validate_statements(statements, is_trust=True)
    if invalid_statements:
        return _invalid_statements_result(invalid_statements)

    findings: List[Dict[str, Any]] = []
    explicit_deny_present = False

    for idx, stmt in enumerate(statements):
        if _is_deny(stmt):
            explicit_deny_present = True
            continue

        tier = _scope_tier(stmt)               # 'precise' | 'broad' | 'none'
        has_cd_guard = _has_effective_cd_guard(stmt)
        present_keys = _condition_keys(stmt)   # all condition keys, for federation sub/aud presence
        actions = _normalize_actions(stmt)
        aws_principals = _principal_field(stmt, "AWS")
        federated = _principal_field(stmt, "Federated")

        if "NotPrincipal" in stmt:
            # "Allow + NotPrincipal" trusts everyone EXCEPT the listed principals
            # — semantically a near-wildcard, which AWS recommends never using.
            severity = "HIGH" if tier != "none" else "CRITICAL"
            findings.append(_make_finding(
                "TRUST_NOTPRINCIPAL",
                "Allow statement uses NotPrincipal",
                severity,
                "This statement trusts every principal except the ones listed — effectively a wildcard. AWS recommends never using NotPrincipal with Allow.",
                idx,
            ))

        if _principal_is_wildcard(stmt):
            severity = {"none": "CRITICAL", "broad": "HIGH", "precise": "MEDIUM"}[tier]
            if tier == "none":
                desc = "Any AWS principal in any account can assume this role; there is no effective scoping Condition."
            elif tier == "broad":
                desc = "A wildcard principal is narrowed to an account, organization, or network, but that is still a broad set of principals."
            else:
                desc = ("Current exposure is limited to the specific principal named in the Condition, but trusting a wildcard principal rescued by a single Condition is fragile — loosening or removing that Condition silently reopens it to every account. Prefer naming the principal directly.")
            findings.append(_make_finding("TRUST_PRINCIPAL_WILDCARD", "Wildcard principal can assume the role", severity, desc, idx))
        else:
            account_principals = [p for p in aws_principals if _is_account_principal(p)]
            if account_principals:
                severity = "MEDIUM" if tier != "none" else "HIGH"
                findings.append(_make_finding(
                    "TRUST_ACCOUNT_ROOT",
                    "Trust is scoped to an entire account",
                    severity,
                    "The principal is an account root/ID, which trusts every principal in that account rather than a specific role or user.",
                    idx,
                ))
                if not has_cd_guard:
                    findings.append(_make_finding(
                        "TRUST_CROSS_ACCOUNT_NO_EXTERNALID",
                        "Account trust without confused-deputy guard",
                        "HIGH",
                        "An account-wide AWS principal is trusted without sts:ExternalId, aws:PrincipalOrgID, or an aws:Source* condition, leaving the role open to the confused-deputy problem.",
                        idx,
                    ))

        is_saml = _contains_action(actions, ASSUME_SAML_ACTION) or any(":saml-provider/" in f.lower() for f in federated)
        is_web_identity = (
            _contains_action(actions, ASSUME_WEB_IDENTITY_ACTION)
            or any(":oidc-provider/" in f.lower() for f in federated)
            or (bool(federated) and not is_saml)
        )

        if is_web_identity:
            # Scoped only if a :sub/:aud value is present AND not a bare wildcard.
            # A `:sub` of "*" trusts every identity from the provider — the same
            # exposure as having no condition at all.
            subject_values = _federation_subject_values(stmt)
            has_effective_subject = any(v != "*" for v in subject_values)
            if not has_effective_subject:
                findings.append(_make_finding(
                    "TRUST_FEDERATED_UNSCOPED",
                    "Federated (OIDC) trust without subject/audience condition",
                    "HIGH",
                    "Web-identity federation is trusted without an effective :sub or :aud Condition (absent, or a bare wildcard value), so any identity from the provider (e.g. any repository or user) can assume the role.",
                    idx,
                ))
        elif is_saml:
            if "saml:aud" not in present_keys:
                findings.append(_make_finding(
                    "TRUST_SAML_UNSCOPED",
                    "SAML trust without saml:aud condition",
                    "MEDIUM",
                    "SAML federation is trusted without a saml:aud Condition restricting the intended audience endpoint.",
                    idx,
                ))

    findings = _dedupe_findings(findings)
    return {
        "valid": True,
        "parse_error": None,
        "analysis_status": "COMPLETE",
        "findings": findings,
        "summary": {"risk_level": _derive_overall_risk(findings)},
        "explicit_deny_present": explicit_deny_present,
        "effective_permissions_calculated": False,
    }


def _classify_policy(statements: List[Any]) -> str:
    """Classifies the IAM policy document this skill knows how to analyze:
      - identity = no Principal element (permissions on a user/role/group).
      - trust    = Principal with only sts:Assume*-family actions (role trust policy).
      - resource = Principal with other actions — a *service* resource-based policy
                   (S3 bucket, KMS key, SQS, SNS, Lambda, DynamoDB, …). OUT OF
                   SCOPE: this skill is strictly IAM identity + role trust policies."""
    has_principal = any(
        isinstance(s, dict) and ("Principal" in s or "NotPrincipal" in s)
        for s in statements
    )
    if not has_principal:
        return "identity"
    actions: List[str] = []
    for s in statements:
        if isinstance(s, dict):
            actions.extend(_normalize_actions(s))
    # A role trust policy only ever grants sts:Assume*-family actions. Anything
    # else with a Principal is a service resource-based policy (out of scope).
    non_sts = [a for a in actions if not a.startswith("sts:")]
    return "resource" if non_sts else "trust"


def analyze_policy_document(policy_text: str) -> Dict[str, Any]:
    """Top-level entry: classifies a policy document and dispatches it to the
    identity or trust analyzer. Service resource-based policies are out of scope
    and returned unanalyzed. Adds a `policy_type` field to the result."""
    try:
        policy = json.loads(policy_text)
    except Exception as exc:
        return {**_invalid_document(f"Invalid JSON: {exc}"), "policy_type": "unknown"}
    if not isinstance(policy, dict):
        return {**_invalid_document("Policy must be a JSON object."), "policy_type": "unknown"}

    statements = _to_list(policy.get("Statement"))
    policy_type = _classify_policy(statements)
    if policy_type == "identity":
        result = analyze_iam_policy(policy_text)
    elif policy_type == "trust":
        result = analyze_trust_policy(policy_text)
    else:  # resource-based policy — out of scope; do not analyze (avoid misleading findings)
        result = {
            "valid": True,
            "parse_error": None,
            "analysis_status": "NOT_ANALYZED",
            "findings": [],
            "summary": {"risk_level": None},
            "note": (
                "Resource-based policy detected (a Principal combined with "
                "non-sts:Assume* actions — e.g. an S3 bucket, KMS key, SQS, SNS, "
                "Lambda, or DynamoDB resource policy). This skill analyzes IAM "
                "identity and role trust policies only; resource-based policies "
                "are out of scope and were not analyzed."
            ),
        }
    result["policy_type"] = policy_type
    return result


class _ReadError:
    """Marker for a file that could not be read, carried through to the result."""
    def __init__(self, message: str) -> None:
        self.message = message


def _invalid(source: str, message: str) -> Dict[str, Any]:
    return {"source": source, **_invalid_document(message)}


def _analyze_value(source: str, policy_value: Any) -> Dict[str, Any]:
    """Scores one policy document (identity or trust — classified internally).
    policy_value may be a JSON string or an already-parsed dict (manifest
    entries carry parsed objects)."""
    if isinstance(policy_value, str):
        result = analyze_policy_document(policy_value)
    elif isinstance(policy_value, dict):
        result = analyze_policy_document(json.dumps(policy_value))
    else:
        return {**_invalid(source, "Policy must be a JSON object."), "policy_type": "unknown"}
    return {"source": source, **result}


def _is_manifest_entry(obj: Any) -> bool:
    """A manifest entry wraps a policy with a source label: {"source", "policy"}.
    A bare policy document has a "Statement" key — used here to disambiguate."""
    return isinstance(obj, dict) and "policy" in obj and "Statement" not in obj


def _expand(data: Any, default_source: str) -> List[Tuple[str, Any]]:
    """Flattens one parsed JSON input into (source, policy_value) pairs. Accepts
    a single policy, a JSON array of policies, or a manifest array."""
    if isinstance(data, list):
        pairs: List[Tuple[str, Any]] = []
        for i, item in enumerate(data):
            if _is_manifest_entry(item):
                pairs.append((item.get("source") or f"{default_source}[{i}]", item.get("policy")))
            else:
                pairs.append((f"{default_source}[{i}]", item))
        return pairs
    if _is_manifest_entry(data):
        return [(data.get("source") or default_source, data.get("policy"))]
    return [(default_source, data)]


def _collect(text: str, default_source: str) -> List[Tuple[str, Any]]:
    """Parses one input blob into (source, policy_value) pairs. If the blob is
    not valid JSON, it is passed through as a single string so the engine can
    report the JSON error against that source."""
    try:
        data = json.loads(text)
    except Exception:
        return [(default_source, text)]
    return _expand(data, default_source)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic AWS IAM policy rule engine. Scores one or "
                    "more IAM policy documents independently.",
        epilog=(
            "Input (as file args or piped to stdin): a single policy document, a JSON\n"
            "array of policy documents, or a manifest — a JSON array of\n"
            "{\"source\": \"label\", \"policy\": <policy>} objects, where <policy> is a\n"
            "policy object or a JSON string. The manifest is the primary interface;\n"
            "\"source\" labels each result.\n"
            "\n"
            "Exit codes:\n"
            f"  {EXIT_OK}  analysis completed; results emitted as JSON (a per-policy\n"
            "     \"valid\": false is a normal finding, not a failure)\n"
            f"  {EXIT_NO_INPUT}  nothing to analyze (empty stdin / no policy provided)\n"
            f"  {EXIT_READ_ERROR}  at least one named file could not be read"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "policies", nargs="*",
        help="Paths to IAM policy / manifest JSON files. Reads stdin if omitted.",
    )
    args = parser.parse_args()

    inputs: List[Tuple[str, Any]] = []
    had_read_error = False

    if args.policies:
        for path in args.policies:
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    text = fh.read()
            except OSError as exc:
                inputs.append((path, _ReadError(f"Could not read policy: {exc}")))
                had_read_error = True
                continue
            inputs.extend(_collect(text, path))
    else:
        text = sys.stdin.read()
        if not text.strip():
            print(json.dumps({"policies": [_invalid("stdin", "No policy provided.")]}, indent=2))
            return EXIT_NO_INPUT
        inputs.extend(_collect(text, "stdin"))

    results: List[Dict[str, Any]] = []
    for source, value in inputs:
        if isinstance(value, _ReadError):
            results.append(_invalid(source, value.message))
        else:
            results.append(_analyze_value(source, value))

    print(json.dumps({"policies": results}, indent=2))
    # A malformed policy is a legitimate result (carried in the JSON), so it does
    # NOT fail the run. Only an unreadable input file — the script being unable to
    # do its job — yields a non-zero exit.
    return EXIT_READ_ERROR if had_read_error else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
