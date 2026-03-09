# 🛡️ AWS Security Misconfiguration Scanner

An **AWS Inspector-lite** CLI tool that scans your AWS account for common security misconfigurations using `boto3`.

## Features

| Scanner | Checks |
|---------|--------|
| **S3 Buckets** | Public ACLs, open bucket policies, missing encryption, no versioning, no logging |
| **Security Groups** | Ports open to `0.0.0.0/0` or `::/0`, sensitive port exposure (SSH, RDP, DB ports) |
| **IAM** | Admin wildcards (`*:*`), missing MFA, stale access keys, root account keys, weak password policy |
| **Encryption** | Unencrypted EBS volumes/snapshots, unencrypted RDS instances, S3 default encryption |

Findings are reported with severity levels: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO`

## Quick Start

### Prerequisites

- Python 3.8+
- AWS credentials configured (`aws configure` or environment variables)
- Read-only access to your AWS resources

### Install

```bash
pip install -r requirements.txt
```

### Run

```bash
# Scan everything
python -m scanner.main

# Scan specific categories
python -m scanner.main --scan s3,sg

# Use a named AWS profile and region
python -m scanner.main --profile production --region us-west-2

# JSON output (great for CI/CD pipelines)
python -m scanner.main --output json > report.json
```

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║          🛡️  AWS Security Misconfiguration Scanner  🛡️        ║
║                      Inspector-Lite v1.0                     ║
╚══════════════════════════════════════════════════════════════╝

──────────────────────────────────────────────────────────
  🔍 🪣  S3 Bucket Security
──────────────────────────────────────────────────────────

  [HIGH] S3 bucket publicly accessible via ACL
  Resource: my-public-bucket
  ↳ Bucket grants 'READ' to AllUsers (everyone on the internet).
  ✦ Recommendation: Remove public ACL grants.

──────────────────────────────────────────────────────────
  🔍 🔒  Security Group Rules
──────────────────────────────────────────────────────────

  [MEDIUM] Security group open on port 22 (SSH)
  Resource: sg-0abc1234 (web-server-sg)
  ↳ Port 22 (SSH) is accessible from 0.0.0.0/0.
  ✦ Recommendation: Restrict SSH access to known IP ranges.

═══════════════════════════════════════════════════════════
  📊  SCAN SUMMARY
═══════════════════════════════════════════════════════════

  CRITICAL  ░░░░░░░░░░░░░░░░░░░░  0
      HIGH  ██░░░░░░░░░░░░░░░░░░  2
    MEDIUM  █░░░░░░░░░░░░░░░░░░░  1
       LOW  ░░░░░░░░░░░░░░░░░░░░  0
      INFO  ░░░░░░░░░░░░░░░░░░░░  0

  Total findings: 3
```

## Required IAM Permissions

The scanner uses **read-only** API calls. Attach these AWS managed policies to the scanning identity:

- `SecurityAudit`
- `ReadOnlyAccess` (or scope to specific services)

## CI/CD Integration

The scanner exits with code **2** when CRITICAL or HIGH findings are detected, making it ideal for pipeline gates:

```bash
python -m scanner.main --output json > report.json || echo "Security issues found!"
```

```bash
python3 -m scanner.main --profile <profile_name> --region <region_name> --output-file report.txt
```

## Project Structure

```
scanner/
├── __init__.py             # Package metadata
├── main.py                 # CLI entry point & orchestrator
├── findings.py             # Finding model & formatters
├── s3_scanner.py           # S3 bucket checks
├── sg_scanner.py           # Security group checks
├── iam_scanner.py          # IAM policy & user checks
└── encryption_scanner.py   # Encryption checks
```

## License

MIT
