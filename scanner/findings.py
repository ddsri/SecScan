"""Finding model and output formatting for the AWS Security Scanner."""

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
from typing import List, Optional


class Severity(Enum):
    """Severity levels for security findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (lower = more severe)."""
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]

    @property
    def color(self) -> str:
        """ANSI color code for terminal output."""
        return {
            Severity.CRITICAL: "\033[91m",  # Bright red
            Severity.HIGH: "\033[31m",       # Red
            Severity.MEDIUM: "\033[33m",     # Yellow
            Severity.LOW: "\033[36m",        # Cyan
            Severity.INFO: "\033[37m",       # White
        }[self]


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


@dataclass
class Finding:
    """Represents a single security finding."""
    severity: Severity
    title: str
    resource_id: str
    description: str
    recommendation: str
    scanner: str = ""
    region: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "title": self.title,
            "resource_id": self.resource_id,
            "description": self.description,
            "recommendation": self.recommendation,
            "scanner": self.scanner,
            "region": self.region,
        }


def format_finding_text(finding: Finding) -> str:
    """Format a single finding for terminal output."""
    sev = finding.severity
    tag = f"{sev.color}{BOLD}[{sev.value}]{RESET}"
    title = f"{BOLD}{finding.title}{RESET}"
    resource = f"{DIM}Resource: {finding.resource_id}{RESET}"
    desc = f"  ↳ {finding.description}"
    rec = f"  ✦ {DIM}Recommendation: {finding.recommendation}{RESET}"
    return f"\n  {tag} {title}\n  {resource}\n{desc}\n{rec}"


def print_banner():
    """Print scanner banner."""
    banner = f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║          🛡️  AWS Security Misconfiguration Scanner  🛡️        ║
║                      Inspector-Lite v1.0                     ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)


def print_section_header(title: str):
    """Print a section header for a scanner category."""
    print(f"\n{BOLD}{'─' * 60}")
    print(f"  🔍 {title}")
    print(f"{'─' * 60}{RESET}")


def print_summary(findings: List[Finding]):
    """Print a summary table of all findings."""
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    total = len(findings)

    print(f"\n{BOLD}{'═' * 60}")
    print(f"  📊  SCAN SUMMARY")
    print(f"{'═' * 60}{RESET}\n")

    for sev in Severity:
        count = counts[sev]
        bar = "█" * count + "░" * max(0, 20 - count)
        label = f"{sev.color}{BOLD}{sev.value:>8}{RESET}"
        print(f"  {label}  {bar}  {count}")

    print(f"\n  {BOLD}Total findings: {total}{RESET}")

    if counts[Severity.CRITICAL] > 0:
        print(f"\n  {Severity.CRITICAL.color}{BOLD}⚠  CRITICAL issues found! Immediate action required.{RESET}")
    elif counts[Severity.HIGH] > 0:
        print(f"\n  {Severity.HIGH.color}{BOLD}⚠  HIGH severity issues found. Please review promptly.{RESET}")
    elif total == 0:
        print(f"\n  \033[32m{BOLD}✔  No issues found. Your configuration looks good!{RESET}")

    print(f"\n  {DIM}Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print()


def findings_to_json(findings: List[Finding]) -> str:
    """Serialize all findings to JSON."""
    return json.dumps(
        {
            "scan_time": datetime.now().isoformat(),
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )


def findings_to_text(findings: List[Finding]) -> str:
    """Generate a plain-text report (no ANSI codes) suitable for saving to a file."""
    lines = []
    lines.append("=" * 60)
    lines.append("  AWS Security Misconfiguration Scanner — Report")
    lines.append("=" * 60)
    lines.append(f"  Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Total findings: {len(findings)}")
    lines.append("")

    sorted_findings = sorted(findings, key=lambda x: x.severity.rank)
    for f in sorted_findings:
        lines.append(f"  [{f.severity.value}] {f.title}")
        lines.append(f"  Resource: {f.resource_id}")
        lines.append(f"  ↳ {f.description}")
        lines.append(f"  ✦ Recommendation: {f.recommendation}")
        if f.scanner:
            lines.append(f"  Scanner: {f.scanner}")
        lines.append("")

    # Summary
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    lines.append("=" * 60)
    lines.append("  SCAN SUMMARY")
    lines.append("=" * 60)
    for sev in Severity:
        lines.append(f"  {sev.value:>8}: {counts[sev]}")
    lines.append(f"     Total: {len(findings)}")
    lines.append("")

    return "\n".join(lines)
