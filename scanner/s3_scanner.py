"""S3 Bucket Security Scanner - Detects public buckets, missing encryption, and more."""

import boto3
from botocore.exceptions import ClientError
from typing import List

from .findings import Finding, Severity


SCANNER_NAME = "S3 Scanner"


def scan(session: boto3.Session, **kwargs) -> List[Finding]:
    """Scan all S3 buckets for security misconfigurations."""
    findings: List[Finding] = []
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        print(f"  ⚠ Could not list S3 buckets: {e}")
        return findings

    for bucket in buckets:
        name = bucket["Name"]
        findings.extend(_check_public_access_block(s3, name))
        findings.extend(_check_bucket_acl(s3, name))
        findings.extend(_check_bucket_policy(s3, name))
        findings.extend(_check_encryption(s3, name))
        findings.extend(_check_versioning(s3, name))
        findings.extend(_check_logging(s3, name))

    return findings


# ── Individual checks ─────────────────────────────────────────────


def _check_public_access_block(s3, bucket_name: str) -> List[Finding]:
    """Check if PublicAccessBlock is properly configured."""
    findings = []
    try:
        config = s3.get_public_access_block(Bucket=bucket_name)
        pab = config["PublicAccessBlockConfiguration"]
        disabled_settings = []

        for setting in [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]:
            if not pab.get(setting, False):
                disabled_settings.append(setting)

        if disabled_settings:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="S3 bucket public access block not fully enabled",
                resource_id=bucket_name,
                description=f"Disabled settings: {', '.join(disabled_settings)}",
                recommendation="Enable all four PublicAccessBlock settings to prevent public access.",
                scanner=SCANNER_NAME,
            ))
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            findings.append(Finding(
                severity=Severity.HIGH,
                title="S3 bucket has no Public Access Block configuration",
                resource_id=bucket_name,
                description="No PublicAccessBlock configuration exists for this bucket.",
                recommendation="Enable PublicAccessBlock on the bucket to prevent accidental public exposure.",
                scanner=SCANNER_NAME,
            ))
    return findings


def _check_bucket_acl(s3, bucket_name: str) -> List[Finding]:
    """Check bucket ACL for public grants."""
    findings = []
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")

            if "AllUsers" in uri:
                permission = grant.get("Permission", "Unknown")
                sev = Severity.CRITICAL if permission in ("FULL_CONTROL", "WRITE") else Severity.HIGH
                findings.append(Finding(
                    severity=sev,
                    title="S3 bucket publicly accessible via ACL",
                    resource_id=bucket_name,
                    description=f"Bucket grants '{permission}' to AllUsers (everyone on the internet).",
                    recommendation="Remove public ACL grants. Use bucket policies with specific principals instead.",
                    scanner=SCANNER_NAME,
                ))
            elif "AuthenticatedUsers" in uri:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="S3 bucket accessible to all AWS authenticated users",
                    resource_id=bucket_name,
                    description=f"Bucket grants '{grant.get('Permission', 'Unknown')}' to AuthenticatedUsers.",
                    recommendation="Remove this overly broad grant. Specify exact AWS accounts instead.",
                    scanner=SCANNER_NAME,
                ))
    except ClientError:
        pass
    return findings


def _check_bucket_policy(s3, bucket_name: str) -> List[Finding]:
    """Check bucket policy for public access statements."""
    findings = []
    try:
        import json
        policy_str = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
        policy = json.loads(policy_str)

        for statement in policy.get("Statement", []):
            effect = statement.get("Effect", "")
            principal = statement.get("Principal", {})

            if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                condition = statement.get("Condition", {})
                if not condition:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title="S3 bucket policy allows public access",
                        resource_id=bucket_name,
                        description="Bucket policy contains an Allow statement with Principal '*' and no conditions.",
                        recommendation="Restrict the Principal to specific accounts/roles or add Conditions.",
                        scanner=SCANNER_NAME,
                    ))
                else:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="S3 bucket policy allows public access with conditions",
                        resource_id=bucket_name,
                        description="Bucket policy allows Principal '*' but has Condition constraints.",
                        recommendation="Review the policy conditions to ensure they are sufficiently restrictive.",
                        scanner=SCANNER_NAME,
                    ))
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            pass  # No policy is fine
    return findings


def _check_encryption(s3, bucket_name: str) -> List[Finding]:
    """Check bucket default encryption."""
    findings = []
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="S3 bucket has no default encryption",
                resource_id=bucket_name,
                description="Server-side encryption is not configured as a default for this bucket.",
                recommendation="Enable default encryption with SSE-S3 (AES-256) or SSE-KMS.",
                scanner=SCANNER_NAME,
            ))
    return findings


def _check_versioning(s3, bucket_name: str) -> List[Finding]:
    """Check if versioning is enabled."""
    findings = []
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        status = versioning.get("Status", "Disabled")
        if status != "Enabled":
            findings.append(Finding(
                severity=Severity.LOW,
                title="S3 bucket versioning not enabled",
                resource_id=bucket_name,
                description=f"Bucket versioning status: {status}.",
                recommendation="Enable versioning to protect against accidental deletions and overwrites.",
                scanner=SCANNER_NAME,
            ))
    except ClientError:
        pass
    return findings


def _check_logging(s3, bucket_name: str) -> List[Finding]:
    """Check if server access logging is enabled."""
    findings = []
    try:
        logging_config = s3.get_bucket_logging(Bucket=bucket_name)
        if "LoggingEnabled" not in logging_config:
            findings.append(Finding(
                severity=Severity.LOW,
                title="S3 bucket access logging not enabled",
                resource_id=bucket_name,
                description="Server access logging is not configured for this bucket.",
                recommendation="Enable access logging to track requests for security auditing.",
                scanner=SCANNER_NAME,
            ))
    except ClientError:
        pass
    return findings
