#!/usr/bin/env python3
"""Complete Week 7 integration tests."""

import sys
import os
from pathlib import Path
import tempfile
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from securescan.core.scanner import Scanner
from securescan.utils.config import Config, init_config
from securescan.utils.exceptions import InvalidConfigError
from securescan.utils.logger import setup_logging, get_logger


def test_1_configuration_system():
    """Test 1: Configuration system."""
    print("\n" + "="*70)
    print("TEST 1: Configuration System")
    print("="*70)
    
    print("\n✓ Testing default configuration...")
    config = Config()
    assert config.scan.timeout == 300
    assert config.llm.provider == "openai"
    print("  ✅ Default config works")
    
    print("\n✓ Testing validation...")
    config.validate()
    print("  ✅ Validation works")
    
    print("\n✓ Testing invalid config...")
    config.scan.timeout = -1
    try:
        config.validate()
        assert False, "Should have raised error"
    except InvalidConfigError:
        print("  ✅ Invalid config detected")
    
    print("\n✅ TEST 1 PASSED")


def test_2_scanner_with_config():
    """Test 2: Scanner with configuration."""
    print("\n" + "="*70)
    print("TEST 2: Scanner with Configuration")
    print("="*70)
    
    test_dir = Path("test_vuln_detect")
    if not test_dir.exists():
        print("  ⚠️  Skipping: test_vuln_detect not found")
        return
    
    print("\n✓ Testing scanner with custom config...")
    config = Config()
    config.scan.timeout = 120
    
    scanner = Scanner(config=config)
    result = scanner.scan(
        target=test_dir,
        enable_llm=False,
        enable_cve_enrichment=False
    )
    
    assert result.success
    assert result.total_findings > 0
    print(f"  ✅ Scan completed: {result.total_findings} findings")
    
    print("\n✅ TEST 2 PASSED")


def test_3_logging_system():
    """Test 3: Logging system."""
    print("\n" + "="*70)
    print("TEST 3: Logging System")
    print("="*70)
    
    print("\n✓ Testing logging setup...")
    setup_logging(level="INFO", verbose=False)
    logger = get_logger("test")
    logger.info("Test message")
    print("  ✅ Logging works")
    
    print("\n✅ TEST 3 PASSED")


def run_all_tests():
    """Run all Week 7 tests."""
    print("\n" + "="*80)
    print(" "*20 + "WEEK 7 INTEGRATION TESTS")
    print("="*80)
    
    tests = [
        test_1_configuration_system,
        test_2_scanner_with_config,
        test_3_logging_system,
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"\n❌ TEST FAILED: {test_func.__name__}")
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "="*80)
    print("FINAL RESULTS")
    print("="*80)
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    
    if failed == 0:
        print("\n🎉 ALL WEEK 7 TESTS PASSED!")
        print("\n✅ Ready for Week 8: Multi-Deployment!")
    else:
        print("\n❌ Some tests failed")
        sys.exit(1)


if __name__ == "__main__":
    run_all_tests()
