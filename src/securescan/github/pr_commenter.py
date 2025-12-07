"""GitHub PR comment generator."""

import os
import json
from typing import Dict, Any
from pathlib import Path
import requests

from ..core.scanner import ScanResult
from ..utils.logger import get_logger

logger = get_logger(__name__)


class PRCommenter:
    """Generate and post PR comments with scan results."""
    
    def __init__(self, github_token: str):
        """Initialize PR commenter."""
        self.token = github_token
        self.api_url = "https://api.github.com"
        
        # Get GitHub context from environment
        self.repo = os.getenv("GITHUB_REPOSITORY")
        self.pr_number = self._get_pr_number()
    
    def _get_pr_number(self) -> int:
        """Extract PR number from GitHub event."""
        event_path = os.getenv("GITHUB_EVENT_PATH")
        if not event_path:
            return None
        
        try:
            with open(event_path) as f:
                event = json.load(f)
            return event.get("pull_request", {}).get("number")
        except:
            return None
    
    def post_comment(self, result: ScanResult) -> None:
        """Post scan results as PR comment."""
        if not self.pr_number:
            logger.warning("Not a PR event, skipping comment")
            return
        
        comment_body = self._build_comment(result)
        
        # Post comment via GitHub API
        url = f"{self.api_url}/repos/{self.repo}/issues/{self.pr_number}/comments"
        
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }
        
        response = requests.post(
            url,
            headers=headers,
            json={"body": comment_body}
        )
        
        response.raise_for_status()
        logger.info(f"Posted comment to PR #{self.pr_number}")
    
    def _build_comment(self, result: ScanResult) -> str:
        """Build markdown comment body."""
        lines = []
        
        # Header
        lines.append("## 🔒 SecureScan AI Security Review")
        lines.append("")
        
        # Summary
        if result.total_findings == 0:
            lines.append("### ✅ No security issues found!")
            lines.append("")
            lines.append("Great job! No vulnerabilities were detected in this PR.")
        else:
            # Severity badge
            critical = result.findings_by_severity.get("CRITICAL", 0)
            high = result.findings_by_severity.get("HIGH", 0)
            medium = result.findings_by_severity.get("MEDIUM", 0)
            low = result.findings_by_severity.get("LOW", 0)
            
            lines.append("### 📊 Scan Summary")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            
            if critical > 0:
                lines.append(f"| 🔴 **CRITICAL** | **{critical}** |")
            if high > 0:
                lines.append(f"| 🟠 **HIGH** | **{high}** |")
            if medium > 0:
                lines.append(f"| 🟡 MEDIUM | {medium} |")
            if low > 0:
                lines.append(f"| 🔵 LOW | {low} |")
            
            lines.append("")
            
            # Critical/High findings detail
            critical_high = [
                f for f in result.findings
                if f.get("severity") in ("CRITICAL", "HIGH")
            ]
            
            if critical_high:
                lines.append("### ⚠️ Critical & High Severity Findings")
                lines.append("")
                
                for i, finding in enumerate(critical_high[:5], 1):
                    severity_emoji = "🔴" if finding["severity"] == "CRITICAL" else "🟠"
                    
                    lines.append(f"#### {i}. {severity_emoji} **{finding['title']}**")
                    lines.append("")
                    lines.append(f"- **File:** `{Path(finding['file']).name}:{finding['line']}`")
                    lines.append(f"- **Category:** {finding.get('category', 'N/A')}")
                    
                    if finding.get("cwe_id"):
                        lines.append(f"- **CWE:** {finding['cwe_id']}")
                    
                    # AI analysis
                    if finding.get("llm_validated"):
                        confidence = finding.get("llm_confidence", 0)
                        lines.append(f"- **AI Confidence:** {confidence:.0%}")
                    
                    # CVE info
                    if finding.get("cve_enriched"):
                        cve_count = finding.get("cve_count", 0)
                        max_cvss = finding.get("max_cvss", 0)
                        lines.append(f"- **Related CVEs:** {cve_count} (Max CVSS: {max_cvss:.1f})")
                        
                        if finding.get("cisa_kev"):
                            lines.append(f"- **🚨 CISA KEV:** Actively exploited in the wild!")
                    
                    lines.append("")
                
                if len(critical_high) > 5:
                    lines.append(f"*... and {len(critical_high) - 5} more*")
                    lines.append("")
        
        # Stats
        lines.append("---")
        lines.append("")
        lines.append("### 📈 Scan Details")
        lines.append("")
        lines.append(f"- **Files scanned:** {result.files_scanned}")
        lines.append(f"- **Total findings:** {result.total_findings}")
        lines.append(f"- **Duration:** {result.duration_seconds:.1f}s")
        
        # AI stats
        if "llm_validation" in result.config:
            llm = result.config["llm_validation"]
            lines.append(f"- **AI validated:** {llm['validated']} findings")
            lines.append(f"- **False positives filtered:** {llm['false_positives']}")
        
        # CVE stats
        if "cve_enrichment" in result.config and "error" not in result.config["cve_enrichment"]:
            cve = result.config["cve_enrichment"]
            lines.append(f"- **CVE enriched:** {cve['enriched_findings']} findings")
            lines.append(f"- **Total CVEs:** {cve['total_cves_found']}")
        
        lines.append("")
        lines.append("---")
        lines.append("*Powered by [SecureScan AI](https://github.com/your-org/securescan-ai)*")
        
        return "\n".join(lines)
