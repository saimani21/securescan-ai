"""GitHub commit status checker."""

import os
from typing import Dict, Any
import requests

from ..core.scanner import ScanResult
from ..utils.logger import get_logger

logger = get_logger(__name__)


class StatusChecker:
    """Update GitHub commit status based on scan results."""
    
    def __init__(self, github_token: str):
        """Initialize status checker."""
        self.token = github_token
        self.api_url = "https://api.github.com"
        self.repo = os.getenv("GITHUB_REPOSITORY")
        self.sha = os.getenv("GITHUB_SHA")
    
    def update_status(self, result: ScanResult, fail_on: str) -> bool:
        """
        Update commit status and return whether build should pass.
        
        Args:
            result: Scan result
            fail_on: Severity level to fail on (CRITICAL, HIGH, MEDIUM, LOW, NONE)
            
        Returns:
            True if build should pass, False otherwise
        """
        fail_on = fail_on.upper()
        
        # Determine if build should pass
        passed = self._should_pass(result, fail_on)
        
        # Build status
        state = "success" if passed else "failure"
        description = self._build_description(result, fail_on)
        
        # Post status via GitHub API
        url = f"{self.api_url}/repos/{self.repo}/statuses/{self.sha}"
        
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }
        
        payload = {
            "state": state,
            "description": description,
            "context": "SecureScan AI",
            "target_url": f"https://github.com/{self.repo}/actions"
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            logger.info(f"Updated commit status: {state}")
        except Exception as e:
            logger.error(f"Failed to update commit status: {e}")
        
        return passed
    
    def _should_pass(self, result: ScanResult, fail_on: str) -> bool:
        """Determine if build should pass based on fail_on threshold."""
        if fail_on == "NONE":
            return True
        
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        
        # Get index of fail_on severity
        try:
            fail_index = severity_order.index(fail_on)
        except ValueError:
            return True
        
        # Check if any findings are >= fail_on severity
        for severity in severity_order[: fail_index + 1]:
            if result.findings_by_severity.get(severity, 0) > 0:
                return False
        
        return True
    
    def _build_description(self, result: ScanResult, fail_on: str) -> str:
        """Build status description."""
        if result.total_findings == 0:
            return "✅ No security issues found"
        
        critical = result.findings_by_severity.get("CRITICAL", 0)
        high = result.findings_by_severity.get("HIGH", 0)
        medium = result.findings_by_severity.get("MEDIUM", 0)
        
        parts = []
        if critical > 0:
            parts.append(f"{critical} critical")
        if high > 0:
            parts.append(f"{high} high")
        if medium > 0:
            parts.append(f"{medium} medium")
        
        findings_text = ", ".join(parts)
        
        passed = self._should_pass(result, fail_on)
        emoji = "✅" if passed else "❌"
        
        return f"{emoji} {result.total_findings} findings ({findings_text})"
