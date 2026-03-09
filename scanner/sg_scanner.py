"""Security Group Scanner - Detects overly permissive inbound rules."""

import boto3
from botocore.exceptions import ClientError
from typing import List

from .findings import Finding, Severity


SCANNER_NAME = "Security Group Scanner"

# Well-known sensitive ports
SENSITIVE_PORTS = {
    22: ("SSH", Severity.HIGH),
    3389: ("RDP", Severity.HIGH),
    3306: ("MySQL", Severity.MEDIUM),
    5432: ("PostgreSQL", Severity.MEDIUM),
    1433: ("MSSQL", Severity.MEDIUM),
    1521: ("Oracle DB", Severity.MEDIUM),
    27017: ("MongoDB", Severity.MEDIUM),
    6379: ("Redis", Severity.MEDIUM),
    11211: ("Memcached", Severity.MEDIUM),
    9200: ("Elasticsearch", Severity.MEDIUM),
    5601: ("Kibana", Severity.MEDIUM),
    8080: ("HTTP-Alt", Severity.LOW),
    8443: ("HTTPS-Alt", Severity.LOW),
    23: ("Telnet", Severity.HIGH),
    21: ("FTP", Severity.HIGH),
}


def scan(session: boto3.Session, **kwargs) -> List[Finding]:
    """Scan all security groups for overly permissive rules."""
    findings: List[Finding] = []
    region = kwargs.get("region", session.region_name or "us-east-1")
    ec2 = session.client("ec2", region_name=region)

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                findings.extend(_check_security_group(sg, region))
    except ClientError as e:
        print(f"  ⚠ Could not describe security groups: {e}")

    return findings


def _check_security_group(sg: dict, region: str) -> List[Finding]:
    """Analyse a single security group's inbound rules."""
    findings = []
    sg_id = sg["GroupId"]
    sg_name = sg.get("GroupName", "unnamed")
    resource_label = f"{sg_id} ({sg_name})"

    for rule in sg.get("IpPermissions", []):
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        protocol = rule.get("IpProtocol", "-1")

        # Collect all open CIDRs (IPv4 + IPv6)
        open_cidrs = []
        for ip_range in rule.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                open_cidrs.append("0.0.0.0/0")
        for ip_range in rule.get("Ipv6Ranges", []):
            if ip_range.get("CidrIpv6") == "::/0":
                open_cidrs.append("::/0")

        if not open_cidrs:
            continue  # Rule is not open to the world

        cidr_str = ", ".join(open_cidrs)

        # Case 1: All traffic allowed (protocol -1)
        if protocol == "-1":
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Security group allows ALL inbound traffic from the internet",
                resource_id=resource_label,
                description=f"All protocols/ports open to {cidr_str}.",
                recommendation="Restrict inbound rules to specific ports and source IP ranges.",
                scanner=SCANNER_NAME,
                region=region,
            ))
            continue

        # Case 2: Wide port range (e.g. 0-65535)
        if from_port == 0 and to_port == 65535:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Security group allows all ports on a protocol from the internet",
                resource_id=resource_label,
                description=f"Protocol {protocol}, ports 0-65535 open to {cidr_str}.",
                recommendation="Restrict to only the specific ports your application needs.",
                scanner=SCANNER_NAME,
                region=region,
            ))
            continue

        # Case 3: Check individual sensitive ports
        matched = False
        for port, (service, severity) in SENSITIVE_PORTS.items():
            if from_port <= port <= to_port:
                findings.append(Finding(
                    severity=severity,
                    title=f"Security group open on port {port} ({service})",
                    resource_id=resource_label,
                    description=f"Port {port} ({service}) is accessible from {cidr_str}.",
                    recommendation=f"Restrict {service} access to known IP ranges or use a VPN/bastion host.",
                    scanner=SCANNER_NAME,
                    region=region,
                ))
                matched = True

        # Case 4: Non-sensitive port but still open
        if not matched:
            port_range = f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
            findings.append(Finding(
                severity=Severity.LOW,
                title=f"Security group open on port {port_range} to the internet",
                resource_id=resource_label,
                description=f"Port(s) {port_range} (protocol {protocol}) accessible from {cidr_str}.",
                recommendation="Verify this port needs to be publicly accessible. Restrict if possible.",
                scanner=SCANNER_NAME,
                region=region,
            ))

    return findings
