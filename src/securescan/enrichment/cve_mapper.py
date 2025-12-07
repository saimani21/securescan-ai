"""CWE to CVE mapping with enrichment."""

from typing import List, Dict, Any, Optional
from .nvd_client import NVDClient
from ..utils.logger import get_logger

logger = get_logger(__name__)


class CVEMapper:
    """
    Maps CWE IDs to related CVEs and enriches findings.
    
    Features:
    - CWE → CVE lookup
    - CVSS score aggregation
    - Severity analysis
    - Reference extraction
    """
    
    def __init__(self, nvd_client: NVDClient):
        """
        Initialize CVE mapper.
        
        Args:
            nvd_client: NVD API client instance
        """
        self.nvd_client = nvd_client
    
    def enrich_finding(
        self,
        finding: Dict[str, Any],
        max_cves: int = 10
    ) -> Dict[str, Any]:
        """
        Enrich finding with CVE data.
        
        Args:
            finding: Finding dictionary with CWE ID
            max_cves: Maximum CVEs to fetch (default: 10)
            
        Returns:
            Finding enriched with CVE data
        """
        cwe_id = finding.get("cwe_id")
        
        if not cwe_id:
            logger.debug(f"No CWE ID in finding: {finding.get('title')}")
            return finding
        
        logger.debug(f"Enriching finding with CVEs for {cwe_id}")
        
        # Get CVEs for this CWE
        cves = self.get_cves_for_cwe(cwe_id, limit=max_cves)
        
        if not cves:
            logger.debug(f"No CVEs found for {cwe_id}")
            finding["cve_enriched"] = False
            return finding
        
        # Calculate statistics
        cvss_scores = [cve["cvss_score"] for cve in cves if cve.get("cvss_score")]
        
        # Add CVE enrichment data
        finding["cve_enriched"] = True
        finding["related_cves"] = cves
        finding["cve_count"] = len(cves)
        
        if cvss_scores:
            finding["avg_cvss"] = sum(cvss_scores) / len(cvss_scores)
            finding["max_cvss"] = max(cvss_scores)
            finding["min_cvss"] = min(cvss_scores)
        else:
            finding["avg_cvss"] = None
            finding["max_cvss"] = None
            finding["min_cvss"] = None
        
        # Extract most severe CVE
        if cves:
            most_severe = max(
                cves,
                key=lambda c: c.get("cvss_score", 0)
            )
            finding["most_severe_cve"] = most_severe
        
        logger.info(
            f"Enriched {cwe_id}: {len(cves)} CVEs, "
            f"avg CVSS: {finding.get('avg_cvss', 0):.1f}"
        )
        
        return finding
    
    def get_cves_for_cwe(
        self,
        cwe_id: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get CVEs for a CWE ID.
        
        Args:
            cwe_id: CWE ID (e.g., "CWE-89" or "89")
            limit: Max CVEs to return
            
        Returns:
            List of CVE dictionaries sorted by CVSS score (descending)
        """
        cves = self.nvd_client.search_by_cwe(cwe_id, limit=limit)
        
        # Sort by CVSS score (highest first)
        cves.sort(
            key=lambda c: c.get("cvss_score", 0),
            reverse=True
        )
        
        return cves
    
    def get_cve_summary(self, cves: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for CVE list.
        
        Args:
            cves: List of CVE dictionaries
            
        Returns:
            Summary statistics
        """
        if not cves:
            return {
                "total": 0,
                "with_scores": 0,
                "avg_cvss": None,
                "max_cvss": None,
                "severity_breakdown": {},
            }
        
        # Extract scores
        scores = [cve.get("cvss_score") for cve in cves if cve.get("cvss_score")]
        
        # Severity breakdown
        severity_breakdown = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        
        for cve in cves:
            severity = cve.get("cvss_severity", "").upper()
            if severity in severity_breakdown:
                severity_breakdown[severity] += 1
        
        return {
            "total": len(cves),
            "with_scores": len(scores),
            "avg_cvss": sum(scores) / len(scores) if scores else None,
            "max_cvss": max(scores) if scores else None,
            "min_cvss": min(scores) if scores else None,
            "severity_breakdown": severity_breakdown,
        }
