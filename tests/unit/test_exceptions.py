"""Unit tests for exception handling."""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from securescan.utils.exceptions import (
    SecureScanError, ScanError, ConfigError,
    LLMError, InvalidConfigError
)


def test_base_exception():
    """Test base exception."""
    error = SecureScanError(
        "Test error",
        details={"key": "value"},
        suggestion="Try this fix"
    )
    
    message = str(error)
    assert "Test error" in message
    assert "key: value" in message
    assert "Try this fix" in message


def test_scan_error():
    """Test scan error."""
    error = ScanError("Scan failed")
    assert isinstance(error, SecureScanError)


def test_config_error():
    """Test config error."""
    error = InvalidConfigError(
        "Invalid timeout",
        suggestion="Set timeout >= 1"
    )
    
    assert "Invalid timeout" in str(error)
    assert "Set timeout >= 1" in str(error)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
