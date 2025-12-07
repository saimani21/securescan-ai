"""Integration tests for complete scanning pipeline."""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from securescan.core.scanner import Scanner
from securescan.utils.config import Config


@pytest.fixture
def test_dir():
    """Get test vulnerability directory."""
    test_path = Path("test_vuln_detect")
    if not test_path.exists():
        pytest.skip("test_vuln_detect directory not found")
    return test_path


def test_basic_scan(test_dir):
    """Test basic SAST scan."""
    scanner = Scanner()
    result = scanner.scan(
        target=test_dir,
        enable_llm=False,
        enable_cve_enrichment=False
    )
    
    assert result.success
    assert result.total_findings > 0
    assert result.files_scanned >= 1


def test_scan_with_severity_filter(test_dir):
    """Test scan with severity filtering."""
    scanner = Scanner()
    result = scanner.scan(
        target=test_dir,
        severity_filter=["HIGH", "CRITICAL"],
        enable_llm=False,
        enable_cve_enrichment=False
    )
    
    # All findings should be HIGH or CRITICAL
    for finding in result.findings:
        assert finding["severity"] in ["HIGH", "CRITICAL"]


def test_scan_with_config(test_dir):
    """Test scan with custom configuration."""
    config = Config()
    config.scan.timeout = 120
    
    scanner = Scanner(config=config)
    result = scanner.scan(
        target=test_dir,
        enable_llm=False,
        enable_cve_enrichment=False
    )
    
    assert result.success


def test_scan_performance(test_dir):
    """Test scan completes within reasonable time."""
    scanner = Scanner()
    result = scanner.scan(
        target=test_dir,
        enable_llm=False,
        enable_cve_enrichment=False
    )
    
    # Should complete within 60 seconds for small test dir
    assert result.duration_seconds < 60


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
