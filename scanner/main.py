"""
AWS Security Misconfiguration Scanner — CLI entry point & orchestrator.

Usage:
    python -m scanner.main [OPTIONS]

    Options:
        --profile PROFILE       AWS CLI profile name (default: default)
        --region REGION         AWS region (default: from profile/env)
        --scan SCANNERS         Comma-separated scanners: s3,sg,iam,encryption (default: all)
        --output FORMAT         Output format: text, json (default: text)
        --output-file FILEPATH  Save report to file (text or json based on --output)
        -h, --help          Show help message
"""

import argparse
import sys
import time

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)

from .findings import (
    Finding,
    format_finding_text,
    print_banner,
    print_section_header,
    print_summary,
    findings_to_json,
    findings_to_text,
    BOLD,
    DIM,
    RESET,
)
from . import s3_scanner, sg_scanner, iam_scanner, encryption_scanner


# ── Scanner registry ──────────────────────────────────────────────

SCANNERS = {
    "s3": {
        "module": s3_scanner,
        "label": "S3 Bucket Security",
        "icon": "🪣",
    },
    "sg": {
        "module": sg_scanner,
        "label": "Security Group Rules",
        "icon": "🔒",
    },
    "iam": {
        "module": iam_scanner,
        "label": "IAM Policies & Users",
        "icon": "👤",
    },
    "encryption": {
        "module": encryption_scanner,
        "label": "Resource Encryption",
        "icon": "🔐",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="🛡️  AWS Security Misconfiguration Scanner — Inspector-Lite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python -m scanner.main                                    # Run all scanners
  python -m scanner.main --scan s3,sg                       # Only S3 and Security Groups
  python -m scanner.main --profile prod --region us-west-2
  python -m scanner.main --output json > report.json
  python -m scanner.main --output-file report.txt           # Save text report to file
  python -m scanner.main --output json --output-file r.json # Save JSON report to file
        """,
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS CLI profile name (default: default profile)",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region to scan (default: profile/env default)",
    )
    parser.add_argument(
        "--scan",
        default="all",
        help="Comma-separated list of scanners: s3, sg, iam, encryption (default: all)",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output-file",
        default=None,
        metavar="FILEPATH",
        help="Save report to a file (format determined by --output)",
    )
    return parser.parse_args()


def create_session(profile: str = None, region: str = None) -> boto3.Session:
    """Create a boto3 session with the specified profile and region."""
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def run_scanners(session: boto3.Session, selected: list, region: str, output_format: str):
    """Orchestrate the selected scanners and print results."""
    all_findings: list[Finding] = []
    is_text = output_format == "text"

    for key in selected:
        scanner_info = SCANNERS[key]
        module = scanner_info["module"]

        if is_text:
            print_section_header(f"{scanner_info['icon']}  {scanner_info['label']}")
            print(f"  {DIM}Scanning...{RESET}", end="", flush=True)

        start = time.time()
        try:
            findings = module.scan(session, region=region)
        except Exception as e:
            if is_text:
                print(f"\r  ⚠ Scanner '{key}' failed: {e}")
            findings = []
        elapsed = time.time() - start

        if is_text:
            print(f"\r  {DIM}Completed in {elapsed:.1f}s — {len(findings)} finding(s){RESET}")

            for f in sorted(findings, key=lambda x: x.severity.rank):
                print(format_finding_text(f))

        all_findings.extend(findings)

    # ── Output ────────────────────────────────────────────────────
    if output_format == "json":
        print(findings_to_json(all_findings))
    else:
        print_summary(all_findings)

    return all_findings


def main():
    args = parse_args()

    if args.output == "text":
        print_banner()

    # ── Resolve scanners ──────────────────────────────────────────
    if args.scan == "all":
        selected = list(SCANNERS.keys())
    else:
        selected = [s.strip().lower() for s in args.scan.split(",")]
        invalid = [s for s in selected if s not in SCANNERS]
        if invalid:
            print(f"Error: Unknown scanner(s): {', '.join(invalid)}")
            print(f"Available: {', '.join(SCANNERS.keys())}")
            sys.exit(1)

    # ── Create session ────────────────────────────────────────────
    try:
        session = create_session(profile=args.profile, region=args.region)
        # Quick credential check
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        if args.output == "text":
            print(f"  {BOLD}Account :{RESET} {identity['Account']}")
            print(f"  {BOLD}Identity:{RESET} {identity['Arn']}")
            print(f"  {BOLD}Region  :{RESET} {args.region or session.region_name or 'us-east-1'}")
            print(f"  {BOLD}Scanners:{RESET} {', '.join(selected)}")

    except NoCredentialsError:
        print("\n❌ No AWS credentials found!")
        print("   Configure credentials using one of:")
        print("   • aws configure")
        print("   • AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars")
        print("   • --profile flag with a named profile")
        sys.exit(1)
    except ProfileNotFound as e:
        print(f"\n❌ {e}")
        sys.exit(1)
    except (BotoCoreError, ClientError) as e:
        print(f"\n❌ AWS connection error: {e}")
        sys.exit(1)

    # ── Run ───────────────────────────────────────────────────────
    region = args.region or session.region_name or "us-east-1"
    findings = run_scanners(session, selected, region, args.output)

    # ── Save to file if requested ─────────────────────────────────
    if args.output_file:
        try:
            if args.output == "json":
                content = findings_to_json(findings)
            else:
                content = findings_to_text(findings)

            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(content)

            if args.output == "text":
                print(f"\n  {BOLD}📄 Report saved to:{RESET} {args.output_file}")
        except OSError as e:
            print(f"\n  ❌ Could not write to {args.output_file}: {e}")

    # Exit code: non-zero if critical/high findings exist
    has_critical = any(f.severity.rank <= 1 for f in findings)
    sys.exit(2 if has_critical else 0)


if __name__ == "__main__":
    main()
