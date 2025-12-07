#!/usr/bin/env python3
"""GitHub Action runner script."""

import sys
import os
import json
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from securescan.core.scanner import Scanner
from securescan.github.pr_commenter import PRCommenter
from securescan.github.sarif_generator import SARIFGenerator
from securescan.github.status_checker import StatusChecker


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=".")
    parser.add_argument("--severity", default="MEDIUM")
    parser.add_argument("--fail-on", default="HIGH")
    parser.add_argument("--enable-llm", default="false")
    parser.add_argument("--llm-provider", default="openai")
    parser.add_argument("--llm-model", default="gpt-4o")
    parser.add_argument("--enrich-cve", default="false")
    parser.add_argument("--output-sarif", default="true")
    parser.add_argument("--comment-pr", default="true")
    parser.add_argument("--auto-label", default="true")
    return parser.parse_args()


def str_to_bool(value: str) -> bool:
    """Convert string to boolean."""
    return value.lower() in ("true", "yes", "1", "on")


def main():
    """Main entry point."""
    args = parse_args()
    
    # Parse severity filter
    severity_map = {
        "CRITICAL": ["CRITICAL"],
        "HIGH": ["CRITICAL", "HIGH"],
        "MEDIUM": ["CRITICAL", "HIGH", "MEDIUM"],
        "LOW": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "INFO": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    }
    severity_filter = severity_map.get(args.severity.upper(), ["HIGH", "CRITICAL"])
    
    print(f"🔍 Starting SecureScan AI")
    print(f"   Target: {args.target}")
    print(f"   Severity filter: {', '.join(severity_filter)}")
    print(f"   AI validation: {args.enable_llm}")
    print(f"   CVE enrichment: {args.enrich_cve}")
    print()
    
    # Run scan
    scanner = Scanner()
    result = scanner.scan(
        target=Path(args.target),
        severity_filter=severity_filter,
        enable_llm=str_to_bool(args.enable_llm),
        llm_provider=args.llm_provider,
        llm_model=args.llm_model,
        enable_cve_enrichment=str_to_bool(args.enrich_cve),
    )
    
    print(f"\n📊 Scan complete:")
    print(f"   Total findings: {result.total_findings}")
    print(f"   By severity: {result.findings_by_severity}")
    print(f"   Duration: {result.duration_seconds:.1f}s")
    
    # Set GitHub outputs
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"findings-count={result.total_findings}\n")
            f.write(f"critical-count={result.findings_by_severity.get('CRITICAL', 0)}\n")
            f.write(f"high-count={result.findings_by_severity.get('HIGH', 0)}\n")
            f.write(f"medium-count={result.findings_by_severity.get('MEDIUM', 0)}\n")
            f.write(f"low-count={result.findings_by_severity.get('LOW', 0)}\n")
    
    # Generate SARIF
    if str_to_bool(args.output_sarif):
        print("\n📄 Generating SARIF report...")
        sarif_gen = SARIFGenerator()
        sarif_file = "securescan-results.sarif"
        sarif_gen.generate(result, sarif_file)
        print(f"   ✅ SARIF saved to {sarif_file}")
        
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"sarif-file={sarif_file}\n")
    
    # Comment on PR
    if str_to_bool(args.comment_pr) and os.getenv("GITHUB_EVENT_NAME") == "pull_request":
        print("\n💬 Posting PR comment...")
        try:
            commenter = PRCommenter(os.getenv("GITHUB_TOKEN"))
            commenter.post_comment(result)
            print("   ✅ PR comment posted")
        except Exception as e:
            print(f"   ⚠️  Failed to post PR comment: {e}")
    
    # Update status check
    print("\n✅ Updating commit status...")
    try:
        status = StatusChecker(os.getenv("GITHUB_TOKEN"))
        passed = status.update_status(result, args.fail_on)
        
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"scan-passed={str(passed).lower()}\n")
        
        if not passed:
            print(f"   ❌ Build failed: Found {args.fail_on}+ severity findings")
            sys.exit(1)
        else:
            print("   ✅ Build passed")
    
    except Exception as e:
        print(f"   ⚠️  Failed to update status: {e}")
    
    print("\n🎉 SecureScan AI complete!")


if __name__ == "__main__":
    main()
