"""SARIF format generator for GitHub Code Scanning."""

import json
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime

from ..core.scanner import ScanResult
from ..utils.logger import get_logger

logger = get_logger(__name__)


class SARIFGenerator:
    """Generate SARIF 2.1.0 format for GitHub Code Scanning."""
    
    SARIF_VERSION = "2.1.0"
    TOOL_NAME = "SecureScan AI"
    TOOL_VERSION = "1.0.0"
    
    def generate(self, result: ScanResult, output_file: str) -> None:
        """Generate SARIF file from scan result."""
        sarif = {
            "version": self.SARIF_VERSION,
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [self._build_run(result)]
        }
        
        # Write to file
        with open(output_file, "w") as f:
            json.dump(sarif, f, indent=2)
        
        logger.info(f"SARIF report saved to {output_file}")
    
    def _build_run(self, result: ScanResult) -> Dict[str, Any]:
        """Build SARIF run object."""
        return {
            "tool": self._build_tool(),
            "results": self._build_results(result),
            "columnKind": "utf16CodeUnits",
        }
    
    def _build_tool(self) -> Dict[str, Any]:
        """Build SARIF tool object."""
        return {
            "driver": {
                "name": self.TOOL_NAME,
                "version": self.TOOL_VERSION,
                "informationUri": "https://github.com/your-org/securescan-ai",
                "rules": []  # Rules will be populated from findings
            }
        }
    
    def _build_results(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """Build SARIF results from findings."""
        results = []
        
        for finding in scan_result.findings:
            result = {
                "ruleId": finding.get("rule_id", "unknown"),
                "level": self._map_severity(finding.get("severity", "warning")),
                "message": {
                    "text": finding.get("title", "Security issue detected")
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("file", "unknown"),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": finding.get("line", 1),
                            "startColumn": finding.get("column", 1),
                            "endLine": finding.get("end_line", finding.get("line", 1)),
                            "endColumn": finding.get("end_column", finding.get("column", 1) + 1),
                        }
                    }
                }],
            }
            
            # Add properties
            properties = {}
            
            if finding.get("cwe_id"):
                properties["cwe"] = finding["cwe_id"]
            
            if finding.get("llm_validated"):
                properties["ai_confidence"] = finding.get("llm_confidence", 0)
                properties["ai_exploitability"] = finding.get("llm_exploitability", "unknown")
            
            if finding.get("cve_enriched"):
                properties["cve_count"] = finding.get("cve_count", 0)
                properties["max_cvss"] = finding.get("max_cvss", 0)
                properties["threat_level"] = finding.get("threat_level", "unknown")
            
            if properties:
                result["properties"] = properties
            
            results.append(result)
        
        return results
    
    def _map_severity(self, severity: str) -> str:
        """Map SecureScan severity to SARIF level."""
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none",
        }
        return mapping.get(severity.upper(), "warning")
