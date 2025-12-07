#!/usr/bin/env python3
"""Test GitHub Action components locally."""

import sys
import os
from pathlib import Path
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from securescan.core.scanner import Scanner
from securescan.github.pr_commenter import PRCommenter
from securescan.github.sarif_generator import SARIFGenerator
from securescan.github.status_checker import StatusChecker


def test_scanner():
    """Test basic scanning functionality."""
    print("="*70)
    print("TEST 1: Scanner Functionality")
    print("="*70)
    
    scanner = Scanner()
    result = scanner.scan(
        target=Path("test_vuln_detect"),
        enable_llm=False,
        enable_cve_enrichment=False
    )
    
    assert result.total_findings > 0, "Should find vulnerabilities"
    assert result.success, "Scan should succeed"
    
    print(f"✅ Scanner test passed: {result.total_findings} findings")
    return result


def test_sarif_generator(scan_result):
    """Test SARIF generation."""
    print("\n" + "="*70)
    print("TEST 2: SARIF Generation")
    print("="*70)
    
    sarif_gen = SARIFGenerator()
    output_file = "test_output.sarif"
    
    sarif_gen.generate(scan_result, output_file)
    
    # Verify SARIF file
    assert Path(output_file).exists(), "SARIF file should be created"
    
    with open(output_file) as f:
        sarif = json.load(f)
    
    assert sarif["version"] == "2.1.0", "Should be SARIF 2.1.0"
    assert len(sarif["runs"]) > 0, "Should have runs"
    assert len(sarif["runs"][0]["results"]) > 0, "Should have results"
    
    print(f"✅ SARIF test passed: {len(sarif['runs'][0]['results'])} results")
    
    # Cleanup
    os.remove(output_file)


def test_pr_comment_format(scan_result):
    """Test PR comment formatting (without posting)."""
    print("\n" + "="*70)
    print("TEST 3: PR Comment Formatting")
    print("="*70)
    
    # Create commenter (won't post without PR context)
    commenter = PRCommenter("fake_token")
    
    # Build comment (internal method)
    comment = commenter._build_comment(scan_result)
    
    assert "SecureScan AI" in comment, "Should have header"
    assert "Scan Summary" in comment or "No security issues" in comment, "Should have summary"
    
    print("✅ PR comment format test passed")
    print("\nSample comment preview:")
    print("-" * 70)
    print(comment[:500] + "...")


def test_status_checker_logic(scan_result):
    """Test status checker logic (without GitHub API)."""
    print("\n" + "="*70)
    print("TEST 4: Status Checker Logic")
    print("="*70)
    
    checker = StatusChecker("fake_token")
    
    # Test different fail_on thresholds
    test_cases = [
        ("NONE", True),
        ("CRITICAL", True if scan_result.findings_by_severity.get("CRITICAL", 0) == 0 else False),
        ("HIGH", True if scan_result.findings_by_severity.get("CRITICAL", 0) == 0 and scan_result.findings_by_severity.get("HIGH", 0) == 0 else False),
    ]
    
    for fail_on, expected in test_cases:
        result = checker._should_pass(scan_result, fail_on)
        print(f"   fail_on={fail_on:<10} -> {'PASS' if result else 'FAIL':<4} (expected: {'PASS' if expected else 'FAIL'})")
        assert result == expected, f"Failed for fail_on={fail_on}"
    
    print("✅ Status checker logic test passed")


def main():
    """Run all tests."""
    print("\n🧪 Testing GitHub Action Components\n")
    
    try:
        # Test 1: Scanner
        result = test_scanner()
        
        # Test 2: SARIF
        test_sarif_generator(result)
        
        # Test 3: PR Comment
        test_pr_comment_format(result)
        
        # Test 4: Status Checker
        test_status_checker_logic(result)
        
        print("\n" + "="*70)
        print("✅ ALL TESTS PASSED!")
        print("="*70)
        print("\n🎉 Your GitHub Action components are working correctly!")
        print("   Ready for integration testing with GitHub")
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
