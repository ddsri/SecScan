"""IAM Security Scanner - Detects weak policies, missing MFA, stale keys, and more."""

import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from typing import List
import json

from .findings import Finding, Severity


SCANNER_NAME = "IAM Scanner"

# Actions considered dangerous when granted with Resource "*"
DANGEROUS_ACTIONS = {
    "iam:*", "iam:CreateUser", "iam:CreateRole", "iam:AttachUserPolicy",
    "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy",
    "iam:CreateAccessKey", "iam:CreateLoginProfile",
    "sts:AssumeRole", "sts:*",
    "s3:*", "ec2:*", "lambda:*", "rds:*",
    "organizations:*", "kms:*",
}


def scan(session: boto3.Session, **kwargs) -> List[Finding]:
    """Scan IAM for security misconfigurations."""
    findings: List[Finding] = []
    iam = session.client("iam")

    findings.extend(_check_root_account(iam))
    findings.extend(_check_password_policy(iam))
    findings.extend(_check_users(iam))
    findings.extend(_check_policies(iam))

    return findings


# ── Root account ──────────────────────────────────────────────────

def _check_root_account(iam) -> List[Finding]:
    """Check root account security posture."""
    findings = []
    try:
        summary = iam.get_account_summary()["SummaryMap"]

        if summary.get("AccountAccessKeysPresent", 0) > 0:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Root account has active access keys",
                resource_id="root-account",
                description="The root account has one or more active access keys.",
                recommendation="Delete root access keys. Use IAM users or roles for programmatic access.",
                scanner=SCANNER_NAME,
            ))

        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Root account does not have MFA enabled",
                resource_id="root-account",
                description="Multi-Factor Authentication is not enabled for the root account.",
                recommendation="Enable MFA on the root account immediately (hardware token preferred).",
                scanner=SCANNER_NAME,
            ))
    except ClientError as e:
        print(f"  ⚠ Could not get account summary: {e}")
    return findings


# ── Password policy ──────────────────────────────────────────────

def _check_password_policy(iam) -> List[Finding]:
    """Check IAM password policy strength."""
    findings = []
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]

        if policy.get("MinimumPasswordLength", 0) < 14:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="IAM password policy minimum length is weak",
                resource_id="password-policy",
                description=f"Minimum password length is {policy.get('MinimumPasswordLength', 'not set')}. Recommended: 14+.",
                recommendation="Set minimum password length to at least 14 characters.",
                scanner=SCANNER_NAME,
            ))

        if not policy.get("RequireSymbols", False):
            findings.append(Finding(
                severity=Severity.LOW,
                title="IAM password policy does not require symbols",
                resource_id="password-policy",
                description="Password policy does not require special characters.",
                recommendation="Enable 'Require at least one non-alphanumeric character'.",
                scanner=SCANNER_NAME,
            ))

        if not policy.get("MaxPasswordAge"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="IAM passwords do not expire",
                resource_id="password-policy",
                description="No maximum password age is configured.",
                recommendation="Set password expiry to 90 days or less.",
                scanner=SCANNER_NAME,
            ))

    except ClientError as e:
        if "NoSuchEntity" in str(e):
            findings.append(Finding(
                severity=Severity.HIGH,
                title="No IAM password policy configured",
                resource_id="password-policy",
                description="The account has no custom password policy; AWS defaults are weak.",
                recommendation="Create a strong password policy requiring length ≥ 14, complexity, and rotation.",
                scanner=SCANNER_NAME,
            ))
    return findings


# ── Users ─────────────────────────────────────────────────────────

def _check_users(iam) -> List[Finding]:
    """Check all IAM users for MFA, stale keys, and inline policies."""
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                findings.extend(_check_user_mfa(iam, username))
                findings.extend(_check_user_access_keys(iam, username))
                findings.extend(_check_user_inline_policies(iam, username))
    except ClientError as e:
        print(f"  ⚠ Could not list IAM users: {e}")
    return findings


def _check_user_mfa(iam, username: str) -> List[Finding]:
    findings = []
    try:
        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
        if not mfa_devices:
            # Only flag if user has console access
            try:
                iam.get_login_profile(UserName=username)
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="IAM user without MFA",
                    resource_id=f"user/{username}",
                    description=f"User '{username}' has console access but no MFA device configured.",
                    recommendation="Enable MFA for all users with console access.",
                    scanner=SCANNER_NAME,
                ))
            except ClientError:
                pass  # No login profile = no console access, MFA not required
    except ClientError:
        pass
    return findings


def _check_user_access_keys(iam, username: str) -> List[Finding]:
    findings = []
    try:
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        now = datetime.now(timezone.utc)

        for key in keys:
            key_id = key["AccessKeyId"]
            created = key["CreateDate"]
            status = key["Status"]
            age_days = (now - created).days

            if status == "Active" and age_days > 90:
                sev = Severity.CRITICAL if age_days > 365 else Severity.HIGH
                findings.append(Finding(
                    severity=sev,
                    title="IAM access key is stale",
                    resource_id=f"user/{username}/key/{key_id}",
                    description=f"Access key is {age_days} days old (created {created.strftime('%Y-%m-%d')}).",
                    recommendation="Rotate access keys at least every 90 days. Prefer IAM roles.",
                    scanner=SCANNER_NAME,
                ))

            if status == "Inactive":
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="Inactive IAM access key exists",
                    resource_id=f"user/{username}/key/{key_id}",
                    description=f"Access key has been deactivated but not deleted.",
                    recommendation="Delete inactive access keys to reduce your attack surface.",
                    scanner=SCANNER_NAME,
                ))
    except ClientError:
        pass
    return findings


def _check_user_inline_policies(iam, username: str) -> List[Finding]:
    findings = []
    try:
        policies = iam.list_user_policies(UserName=username)["PolicyNames"]
        if policies:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="IAM user has inline policies",
                resource_id=f"user/{username}",
                description=f"User has {len(policies)} inline policy(ies): {', '.join(policies[:3])}{'...' if len(policies) > 3 else ''}.",
                recommendation="Use managed policies instead of inline policies for easier auditing and reuse.",
                scanner=SCANNER_NAME,
            ))
    except ClientError:
        pass
    return findings


# ── Managed policies ─────────────────────────────────────────────

def _check_policies(iam) -> List[Finding]:
    """Check customer-managed policies for overly permissive statements."""
    findings = []
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local", OnlyAttached=True):
            for policy in page["Policies"]:
                arn = policy["Arn"]
                version_id = policy["DefaultVersionId"]
                try:
                    doc = iam.get_policy_version(
                        PolicyArn=arn, VersionId=version_id
                    )["PolicyVersion"]["Document"]

                    # doc may be a str or dict depending on SDK version
                    if isinstance(doc, str):
                        doc = json.loads(doc)

                    findings.extend(_analyse_policy_document(doc, arn))
                except ClientError:
                    pass
    except ClientError as e:
        print(f"  ⚠ Could not list IAM policies: {e}")
    return findings


def _analyse_policy_document(doc: dict, arn: str) -> List[Finding]:
    """Analyse a policy document for dangerous permissions."""
    findings = []
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # Full admin: Action "*" + Resource "*"
        if "*" in actions and "*" in resources:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="IAM policy grants full administrator access (*:*)",
                resource_id=arn,
                description="Policy allows ALL actions on ALL resources — equivalent to AdministratorAccess.",
                recommendation="Follow least privilege: grant only the specific permissions needed.",
                scanner=SCANNER_NAME,
            ))
            continue

        # Action wildcard on all resources
        if "*" in actions and "*" not in resources:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="IAM policy uses wildcard Action (*)",
                resource_id=arn,
                description="Policy allows all actions — only scope is limited by Resource.",
                recommendation="Replace Action '*' with specific required actions.",
                scanner=SCANNER_NAME,
            ))

        # Dangerous actions on all resources
        if "*" in resources:
            dangerous_found = [a for a in actions if a.lower() in {d.lower() for d in DANGEROUS_ACTIONS}]
            if dangerous_found:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="IAM policy grants dangerous actions on all resources",
                    resource_id=arn,
                    description=f"Dangerous actions on Resource '*': {', '.join(dangerous_found[:5])}.",
                    recommendation="Scope Resource ARNs to the specific resources required.",
                    scanner=SCANNER_NAME,
                ))

    return findings
