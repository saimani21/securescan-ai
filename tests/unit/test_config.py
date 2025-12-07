"""Unit tests for configuration system."""

import pytest
import tempfile
from pathlib import Path
import yaml

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from securescan.utils.config import Config, init_config
from securescan.utils.exceptions import InvalidConfigError


def test_default_config():
    """Test default configuration values."""
    config = Config()
    
    assert config.scan.timeout == 300
    assert config.scan.max_findings == 1000
    assert config.llm.provider == "openai"
    assert config.llm.confidence_threshold == 0.7
    assert config.cve.enabled == False


def test_config_validation():
    """Test configuration validation."""
    config = Config()
    
    # Valid config should pass
    config.validate()
    
    # Invalid timeout should fail
    config.scan.timeout = -1
    with pytest.raises(InvalidConfigError):
        config.validate()


def test_config_from_file():
    """Test loading configuration from file."""
    # Create temporary config file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump({
            "scan": {"timeout": 180},
            "llm": {"provider": "ollama"},
        }, f)
        config_file = Path(f.name)
    
    try:
        config = init_config(config_file)
        assert config.scan.timeout == 180
        assert config.llm.provider == "ollama"
    finally:
        config_file.unlink()


def test_config_get():
    """Test configuration get method."""
    config = Config()
    
    assert config.get("scan.timeout") == 300
    assert config.get("llm.provider") == "openai"
    assert config.get("invalid.key", "default") == "default"


def test_config_to_dict():
    """Test configuration export to dictionary."""
    config = Config()
    config_dict = config.to_dict()
    
    assert "scan" in config_dict
    assert "llm" in config_dict
    assert "cve" in config_dict
    assert config_dict["scan"]["timeout"] == 300


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
