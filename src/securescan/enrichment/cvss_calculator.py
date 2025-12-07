"""CVSS score calculations (placeholder - will implement in Day 4)."""

from typing import Dict, Any, List, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)


class CVSSCalculator:
    """Calculate and analyze CVSS scores."""
    
    @staticmethod
    def calculate_average(cves: List[Dict[str, Any]]) -> Optional[float]:
        """
        Calculate average CVSS score from CVE list.
        
        Args:
            cves: List of CVE dictionaries
            
        Returns:
            Average CVSS score or None
        """
        scores = [cve.get("cvss_score") for cve in cves if cve.get("cvss_score")]
        
        if not scores:
            return None
        
        return sum(scores) / len(scores)
    
    @staticmethod
    def get_max_score(cves: List[Dict[str, Any]]) -> Optional[float]:
        """
        Get maximum CVSS score from CVE list.
        
        Args:
            cves: List of CVE dictionaries
            
        Returns:
            Max CVSS score or None
        """
        scores = [cve.get("cvss_score") for cve in cves if cve.get("cvss_score")]
        
        if not scores:
            return None
        
        return max(scores)
    
    @staticmethod
    def normalize_score(cvss_score: float) -> float:
        """
        Normalize CVSS score to 0.0-1.0 range.
        
        Args:
            cvss_score: CVSS score (0-10)
            
        Returns:
            Normalized score (0.0-1.0)
        """
        return cvss_score / 10.0
