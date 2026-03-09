"""Encryption Scanner - Detects unencrypted EBS volumes, RDS instances, and S3 buckets."""

import boto3
from botocore.exceptions import ClientError
from typing import List

from .findings import Finding, Severity


SCANNER_NAME = "Encryption Scanner"


def scan(session: boto3.Session, **kwargs) -> List[Finding]:
    """Scan for unencrypted resources across EBS, RDS, and S3."""
    findings: List[Finding] = []
    region = kwargs.get("region", session.region_name or "us-east-1")

    findings.extend(_check_ebs_default_encryption(session, region))
    findings.extend(_check_ebs_volumes(session, region))
    findings.extend(_check_ebs_snapshots(session, region))
    findings.extend(_check_rds_instances(session, region))
    findings.extend(_check_s3_encryption(session))

    return findings


# ── EBS ───────────────────────────────────────────────────────────

def _check_ebs_default_encryption(session: boto3.Session, region: str) -> List[Finding]:
    """Check if EBS default encryption is enabled for the region."""
    findings = []
    try:
        ec2 = session.client("ec2", region_name=region)
        resp = ec2.get_ebs_encryption_by_default()
        if not resp.get("EbsEncryptionByDefault", False):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="EBS default encryption is not enabled",
                resource_id=f"region/{region}",
                description=f"New EBS volumes in {region} will NOT be encrypted by default.",
                recommendation="Enable EBS encryption by default for this region via EC2 → Settings.",
                scanner=SCANNER_NAME,
                region=region,
            ))
    except ClientError as e:
        print(f"  ⚠ Could not check EBS default encryption: {e}")
    return findings


def _check_ebs_volumes(session: boto3.Session, region: str) -> List[Finding]:
    """Check all EBS volumes for encryption."""
    findings = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                if not vol.get("Encrypted", False):
                    vol_id = vol["VolumeId"]
                    state = vol.get("State", "unknown")
                    size = vol.get("Size", "?")

                    # Check if attached
                    attachments = vol.get("Attachments", [])
                    attached_to = ", ".join(
                        a.get("InstanceId", "unknown") for a in attachments
                    ) if attachments else "unattached"

                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="EBS volume is not encrypted",
                        resource_id=vol_id,
                        description=f"{size} GiB volume ({state}), attached to: {attached_to}.",
                        recommendation="Create an encrypted copy of the volume and replace the original.",
                        scanner=SCANNER_NAME,
                        region=region,
                    ))
    except ClientError as e:
        print(f"  ⚠ Could not describe EBS volumes: {e}")
    return findings


def _check_ebs_snapshots(session: boto3.Session, region: str) -> List[Finding]:
    """Check owned EBS snapshots for encryption."""
    findings = []
    try:
        ec2 = session.client("ec2", region_name=region)
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=[account_id]):
            for snap in page["Snapshots"]:
                if not snap.get("Encrypted", False):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="EBS snapshot is not encrypted",
                        resource_id=snap["SnapshotId"],
                        description=f"Snapshot of volume {snap.get('VolumeId', 'unknown')}, "
                                    f"{snap.get('VolumeSize', '?')} GiB.",
                        recommendation="Copy the snapshot with encryption enabled and delete the unencrypted original.",
                        scanner=SCANNER_NAME,
                        region=region,
                    ))
    except ClientError as e:
        print(f"  ⚠ Could not describe EBS snapshots: {e}")
    return findings


# ── RDS ───────────────────────────────────────────────────────────

def _check_rds_instances(session: boto3.Session, region: str) -> List[Finding]:
    """Check all RDS instances for encryption at rest."""
    findings = []
    try:
        rds = session.client("rds", region_name=region)
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                db_id = db["DBInstanceIdentifier"]

                if not db.get("StorageEncrypted", False):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="RDS instance is not encrypted at rest",
                        resource_id=db_id,
                        description=f"Engine: {db.get('Engine', 'unknown')}, "
                                    f"class: {db.get('DBInstanceClass', 'unknown')}.",
                        recommendation="Enable encryption. Note: you must recreate the instance from an encrypted snapshot.",
                        scanner=SCANNER_NAME,
                        region=region,
                    ))

                # Also check public accessibility
                if db.get("PubliclyAccessible", False):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="RDS instance is publicly accessible",
                        resource_id=db_id,
                        description="Database is configured to be reachable from the public internet.",
                        recommendation="Set 'Publicly Accessible' to No unless explicitly required.",
                        scanner=SCANNER_NAME,
                        region=region,
                    ))
    except ClientError as e:
        print(f"  ⚠ Could not describe RDS instances: {e}")
    return findings


# ── S3 (encryption only – complements S3 scanner) ────────────────

def _check_s3_encryption(session: boto3.Session) -> List[Finding]:
    """Check S3 buckets for default encryption (encryption-focused view)."""
    findings = []
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError:
        return findings

    for bucket in buckets:
        name = bucket["Name"]
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

            # Check if using AWS-managed keys (SSE-S3) vs KMS
            for rule in rules:
                sse = rule.get("ApplyServerSideEncryptionByDefault", {})
                algo = sse.get("SSEAlgorithm", "")
                if algo == "AES256":
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title="S3 bucket uses SSE-S3 encryption (AES-256)",
                        resource_id=name,
                        description="Bucket uses AWS-managed keys. Consider KMS for additional control.",
                        recommendation="For sensitive data, use SSE-KMS with a customer-managed key.",
                        scanner=SCANNER_NAME,
                    ))
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="S3 bucket has no default encryption configured",
                    resource_id=name,
                    description="Objects uploaded without specifying encryption will be stored unencrypted.",
                    recommendation="Enable default encryption with SSE-S3 or SSE-KMS.",
                    scanner=SCANNER_NAME,
                ))
    return findings
