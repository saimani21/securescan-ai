"""Enhanced configuration management with multiple sources."""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, List
from dataclasses import dataclass, field

from .logger import get_logger
from .exceptions import ConfigError, InvalidConfigError, MissingConfigError

logger = get_logger(__name__)


@dataclass
class ScanConfig:
    """Scan configuration options."""
    timeout: int = 300
    max_findings: int = 1000
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "node_modules", ".git", "__pycache__", "*.min.js"
    ])


@dataclass
class LLMConfig:
    """LLM configuration options."""
    provider: str = "openai"
    model: str = "gpt-4o"
    timeout: int = 30
    max_retries: int = 3
    confidence_threshold: float = 0.7
    max_workers: int = 3


@dataclass
class CVEConfig:
    """CVE enrichment configuration."""
    enabled: bool = False
    max_cves_per_finding: int = 10
    cache_days: int = 7
    timeout: int = 30


@dataclass
class OutputConfig:
    """Output configuration."""
    format: str = "console"
    verbose: bool = False
    show_code: bool = True
    max_code_lines: int = 5


class Config:
    """
    Enhanced configuration manager.
    
    Priority (highest to lowest):
    1. Environment variables
    2. CLI arguments (passed directly)
    3. Project config (.securescan.yml)
    4. User config (~/.securescan/config.yml)
    5. Default values
    """
    
    CONFIG_FILENAME = ".securescan.yml"
    USER_CONFIG_DIR = Path.home() / ".securescan"
    USER_CONFIG_FILE = USER_CONFIG_DIR / "config.yml"
    
    def __init__(self):
        """Initialize configuration manager."""
        self.scan = ScanConfig()
        self.llm = LLMConfig()
        self.cve = CVEConfig()
        self.output = OutputConfig()
        
        # Load configurations in priority order
        self._load_user_config()
        self._load_project_config()
        self._load_env_config()
        
        logger.debug("Configuration initialized")
    
    def _load_user_config(self) -> None:
        """Load user-level configuration."""
        if not self.USER_CONFIG_FILE.exists():
            logger.debug("No user config found")
            return
        
        try:
            with open(self.USER_CONFIG_FILE) as f:
                config = yaml.safe_load(f)
            
            if config:
                self._apply_config(config)
                logger.info(f"Loaded user config: {self.USER_CONFIG_FILE}")
        
        except Exception as e:
            logger.warning(f"Failed to load user config: {e}")
    
    def _load_project_config(self) -> None:
        """Load project-level configuration."""
        # Look for config in current directory and parents
        current = Path.cwd()
        
        for parent in [current] + list(current.parents):
            config_file = parent / self.CONFIG_FILENAME
            
            if config_file.exists():
                try:
                    with open(config_file) as f:
                        config = yaml.safe_load(f)
                    
                    if config:
                        self._apply_config(config)
                        logger.info(f"Loaded project config: {config_file}")
                    return
                
                except Exception as e:
                    logger.warning(f"Failed to load project config: {e}")
        
        logger.debug("No project config found")
    
    def _load_env_config(self) -> None:
        """Load configuration from environment variables."""
        env_mappings = {
            # Scan
            "SECURESCAN_TIMEOUT": ("scan", "timeout", int),
            "SECURESCAN_MAX_FINDINGS": ("scan", "max_findings", int),
            
            # LLM
            "SECURESCAN_LLM_PROVIDER": ("llm", "provider", str),
            "SECURESCAN_LLM_MODEL": ("llm", "model", str),
            "SECURESCAN_LLM_TIMEOUT": ("llm", "timeout", int),
            "SECURESCAN_LLM_MAX_RETRIES": ("llm", "max_retries", int),
            
            # CVE
            "SECURESCAN_CVE_ENABLED": ("cve", "enabled", lambda x: x.lower() in ("true", "1", "yes")),
            "SECURESCAN_CVE_MAX_PER_FINDING": ("cve", "max_cves_per_finding", int),
            
            # Output
            "SECURESCAN_OUTPUT_FORMAT": ("output", "format", str),
            "SECURESCAN_VERBOSE": ("output", "verbose", lambda x: x.lower() in ("true", "1", "yes")),
        }
        
        for env_var, (section, key, converter) in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                try:
                    converted = converter(value)
                    setattr(getattr(self, section), key, converted)
                    logger.debug(f"Loaded from env: {env_var}={converted}")
                except Exception as e:
                    logger.warning(f"Invalid env var {env_var}={value}: {e}")
    
    def _apply_config(self, config: Dict[str, Any]) -> None:
        """Apply configuration dictionary."""
        # Scan config
        if "scan" in config:
            scan_conf = config["scan"]
            if "timeout" in scan_conf:
                self.scan.timeout = int(scan_conf["timeout"])
            if "max_findings" in scan_conf:
                self.scan.max_findings = int(scan_conf["max_findings"])
            if "exclude_patterns" in scan_conf:
                self.scan.exclude_patterns = scan_conf["exclude_patterns"]
        
        # LLM config
        if "llm" in config:
            llm_conf = config["llm"]
            if "provider" in llm_conf:
                self.llm.provider = llm_conf["provider"]
            if "model" in llm_conf:
                self.llm.model = llm_conf["model"]
            if "timeout" in llm_conf:
                self.llm.timeout = int(llm_conf["timeout"])
            if "max_retries" in llm_conf:
                self.llm.max_retries = int(llm_conf["max_retries"])
            if "confidence_threshold" in llm_conf:
                self.llm.confidence_threshold = float(llm_conf["confidence_threshold"])
        
        # CVE config
        if "cve" in config:
            cve_conf = config["cve"]
            if "enabled" in cve_conf:
                self.cve.enabled = bool(cve_conf["enabled"])
            if "max_cves_per_finding" in cve_conf:
                self.cve.max_cves_per_finding = int(cve_conf["max_cves_per_finding"])
            if "cache_days" in cve_conf:
                self.cve.cache_days = int(cve_conf["cache_days"])
        
        # Output config
        if "output" in config:
            out_conf = config["output"]
            if "format" in out_conf:
                self.output.format = out_conf["format"]
            if "verbose" in out_conf:
                self.output.verbose = bool(out_conf["verbose"])
            if "show_code" in out_conf:
                self.output.show_code = bool(out_conf["show_code"])
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key."""
        parts = key.split(".")
        
        if len(parts) != 2:
            raise InvalidConfigError(
                f"Invalid config key: {key}",
                suggestion="Use format: section.key (e.g., scan.timeout)"
            )
        
        section, attr = parts
        
        if not hasattr(self, section):
            return default
        
        section_obj = getattr(self, section)
        return getattr(section_obj, attr, default)
    
    def validate(self) -> None:
        """Validate configuration values."""
        errors = []
        
        # Validate scan config
        if self.scan.timeout < 1:
            errors.append("scan.timeout must be >= 1")
        
        if self.scan.max_findings < 1:
            errors.append("scan.max_findings must be >= 1")
        
        # Validate LLM config
        if self.llm.provider not in ("openai", "ollama"):
            errors.append(f"Invalid llm.provider: {self.llm.provider}")
        
        if self.llm.confidence_threshold < 0 or self.llm.confidence_threshold > 1:
            errors.append("llm.confidence_threshold must be 0-1")
        
        # Validate CVE config
        if self.cve.max_cves_per_finding < 1:
            errors.append("cve.max_cves_per_finding must be >= 1")
        
        # Validate output config
        if self.output.format not in ("console", "json", "sarif", "html"):
            errors.append(f"Invalid output.format: {self.output.format}")
        
        if errors:
            raise InvalidConfigError(
                "Configuration validation failed",
                details={"errors": errors},
                suggestion="Check your .securescan.yml file"
            )
    
    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary."""
        return {
            "scan": {
                "timeout": self.scan.timeout,
                "max_findings": self.scan.max_findings,
                "exclude_patterns": self.scan.exclude_patterns,
            },
            "llm": {
                "provider": self.llm.provider,
                "model": self.llm.model,
                "timeout": self.llm.timeout,
                "max_retries": self.llm.max_retries,
                "confidence_threshold": self.llm.confidence_threshold,
                "max_workers": self.llm.max_workers,
            },
            "cve": {
                "enabled": self.cve.enabled,
                "max_cves_per_finding": self.cve.max_cves_per_finding,
                "cache_days": self.cve.cache_days,
                "timeout": self.cve.timeout,
            },
            "output": {
                "format": self.output.format,
                "verbose": self.output.verbose,
                "show_code": self.output.show_code,
                "max_code_lines": self.output.max_code_lines,
            }
        }
    
    @classmethod
    def create_user_config(cls, overwrite: bool = False) -> Path:
        """Create default user configuration file."""
        if cls.USER_CONFIG_FILE.exists() and not overwrite:
            raise ConfigError(
                f"User config already exists: {cls.USER_CONFIG_FILE}",
                suggestion="Use --overwrite to replace it"
            )
        
        # Create directory
        cls.USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        # Create default config
        default_config = Config()
        
        with open(cls.USER_CONFIG_FILE, "w") as f:
            yaml.dump(default_config.to_dict(), f, default_flow_style=False, sort_keys=False)
        
        logger.info(f"Created user config: {cls.USER_CONFIG_FILE}")
        return cls.USER_CONFIG_FILE


def init_config(config_path: Optional[Path] = None) -> Config:
    """
    Initialize configuration.
    
    Args:
        config_path: Optional explicit config file path
        
    Returns:
        Initialized Config object
    """
    config = Config()
    
    # Load explicit config if provided
    if config_path:
        if not config_path.exists():
            raise MissingConfigError(
                f"Config file not found: {config_path}",
                suggestion="Check the file path or create a new config"
            )
        
        try:
            with open(config_path) as f:
                explicit_config = yaml.safe_load(f)
            
            if explicit_config:
                config._apply_config(explicit_config)
                logger.info(f"Loaded explicit config: {config_path}")
        
        except Exception as e:
            raise ConfigError(
                f"Failed to load config: {config_path}",
                details={"error": str(e)}
            )
    
    # Validate
    config.validate()
    
    return config
