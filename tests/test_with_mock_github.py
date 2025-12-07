#!/usr/bin/env python3
"""Test with mocked GitHub environment variables."""

import sys
import os
import json
from pathlib import Path
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from securescan.core.scanner import Scanner
from securescan.github.pr_commenter import PRCommenter
from securescan.github.status_checker import StatusChecker


def test_with_github_env():
    """Test with GitHub environment variables set."""
    print("🧪 Testing with GitHub Environment Variables\n")
    
    # Mock GitHub environment
    github_env = {
        "GITHUB_REPOSITORY": "test-org/test-repo",
        "GITHUB_SHA": "abc123def456",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": "/tmp/github_event.json",
        "GITHUB_TOKEN": "fake_token_for_testing",
    }
    
    # Create mock event file
    event_data = {
        "pull_request": {
            "number": 42,
            "head": {"sha": "abc123"},
            "base": {"sha": "def456"}
        }
    }
    
    os.makedirs("/tmp", exist_ok=True)
    with open("/tmp/github_event.json", "w") as f:
        json.dump(event_data, f)
    
    # Apply environment
    with patch.dict(os.environ, github_env):
        print("✅ GitHub environment set:")
        print(f"   Repository: {os.getenv('GITHUB_REPOSITORY')}")
        print(f"   PR Number: 42")
        print(f"   Commit SHA: {os.getenv('GITHUB_SHA')}")
        
        # Test PR Commenter initialization
        print("\n📝 Testing PR Commenter...")
        commenter = PRCommenter("fake_token")
        assert commenter.repo == "test-org/test-repo"
        assert commenter.pr_number == 42
        print("   ✅ PR Commenter initialized correctly")
        
        # Test Status Checker initialization
        print("\n✅ Testing Status Checker...")
        checker = StatusChecker("fake_token")
        assert checker.repo == "test-org/test-repo"
        assert checker.sha == "abc123def456"
        print("   ✅ Status Checker initialized correctly")
    
    # Cleanup
    os.remove("/tmp/github_event.json")
    
    print("\n" + "="*70)
    print("✅ GitHub Environment Test Passed!")
    print("="*70)


if __name__ == "__main__":
    test_with_github_env()
