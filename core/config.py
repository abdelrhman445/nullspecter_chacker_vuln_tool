"""
Configuration Management for NullSpecter
Location: core/config.py
"""

import os
import yaml
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, asdict, field
from enum import Enum

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class ReportFormat(str, Enum):
    HTML = "html"
    JSON = "json"
    PDF = "pdf"
    MARKDOWN = "markdown"
    ALL = "all"

@dataclass
class ScannerConfig:
    """Main configuration for NullSpecter scanner"""
    
    # HTTP Settings
    rate_limit: int = 10  # requests per second
    timeout: int = 30  # seconds
    retry_count: int = 3
    user_agent: str = "NullSpecter/2.0 (Security Scanner)"
    verify_ssl: bool = False
    follow_redirects: bool = True
    max_redirects: int = 10
    
    # Scan Settings
    max_concurrent_scans: int = 3
    # UPDATED: Added new checks to default list including shodan
    default_checks: List[str] = field(default_factory=lambda: [
        'xss', 'sqli', 'idor', 'open_redirect', 
        'security_headers', 'graphql', 'ssrf',
        'js_secrets', 'subdomain', 'shodan'
    ])
    scan_depth: int = 2
    max_pages: int = 100
    
    # Authentication
    auth_token: Optional[str] = None
    auth_type: str = "Bearer"  # Bearer, Basic, etc.
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Output Settings
    report_format: ReportFormat = ReportFormat.HTML
    output_dir: str = "./reports"
    log_level: LogLevel = LogLevel.INFO
    log_dir: str = "./logs"
    verbose: bool = False
    quiet: bool = False
    
    # Security Settings
    random_delay: bool = True
    delay_min: float = 0.1
    delay_max: float = 1.0
    respect_robots_txt: bool = True
    respect_rate_limits: bool = True
    
    # Advanced Settings
    proxy: Optional[str] = None
    proxy_type: str = "http"  # http, socks4, socks5
    thread_pool_size: int = 50
    cache_responses: bool = True
    cache_size: int = 1000
    save_responses: bool = False
    response_dir: str = "./responses"
    
    # Payload Settings
    payload_dir: str = "./payloads"
    custom_payloads: Dict[str, list] = field(default_factory=dict)
    
    # Notification Settings
    enable_notifications: bool = False
    webhook_url: Optional[str] = None
    email_notifications: bool = False
    email_config: Dict[str, str] = field(default_factory=dict)
    
    # Telegram Notifications
    telegram_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    # WAF Evasion
    tamper: bool = False

    # NEW: Shodan Integration
    shodan_api_key: Optional[str] = None
    
    def __post_init__(self):
        """Post initialization processing"""
        # Ensure directories exist
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        if self.save_responses:
            os.makedirs(self.response_dir, exist_ok=True)
        
        # Set default headers if not provided
        if not self.headers:
            self.headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1"
            }
    
    @classmethod
    def from_yaml(cls, filepath: str) -> 'ScannerConfig':
        """Load configuration from YAML file"""
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                config_dict = yaml.safe_load(f) or {}
                return cls(**config_dict)
        return cls()
    
    @classmethod
    def from_json(cls, filepath: str) -> 'ScannerConfig':
        """Load configuration from JSON file"""
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                config_dict = json.load(f) or {}
                return cls(**config_dict)
        return cls()
    
    def to_yaml(self, filepath: str):
        """Save configuration to YAML file"""
        config_dict = asdict(self)
        
        # Convert enums to strings
        for key, value in config_dict.items():
            if isinstance(value, Enum):
                config_dict[key] = value.value
        
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
    
    def to_json(self, filepath: str):
        """Save configuration to JSON file"""
        config_dict = asdict(self)
        
        # Convert enums to strings
        for key, value in config_dict.items():
            if isinstance(value, Enum):
                config_dict[key] = value.value
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config_dict, f, indent=2, ensure_ascii=False)
    
    def merge(self, other_config: Dict[str, Any]) -> 'ScannerConfig':
        """Merge another configuration into this one"""
        for key, value in other_config.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self
    
    def validate(self) -> tuple[bool, list]:
        """Validate configuration"""
        errors = []
        
        # Validate numeric values
        if self.rate_limit <= 0:
            errors.append("Rate limit must be positive")
        
        if self.timeout <= 0:
            errors.append("Timeout must be positive")
        
        if self.max_concurrent_scans <= 0:
            errors.append("Max concurrent scans must be positive")
        
        if self.scan_depth < 1:
            errors.append("Scan depth must be at least 1")
        
        if self.delay_min < 0 or self.delay_max < 0:
            errors.append("Delay values must be non-negative")
        
        if self.delay_min > self.delay_max:
            errors.append("Minimum delay cannot be greater than maximum delay")
        
        # Validate directories
        for dir_path in [self.output_dir, self.log_dir]:
            try:
                os.makedirs(dir_path, exist_ok=True)
                if not os.access(dir_path, os.W_OK):
                    errors.append(f"Directory not writable: {dir_path}")
            except Exception as e:
                errors.append(f"Cannot create directory {dir_path}: {e}")
        
        return len(errors) == 0, errors


class ConfigManager:
    """Manage multiple configurations"""
    
    def __init__(self, config_dir: str = "./config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self.configs = {}
        self.current_config = None
    
    def load_config(self, name: str, filepath: str = None) -> ScannerConfig:
        """Load a configuration by name"""
        if filepath is None:
            filepath = self.config_dir / f"{name}.yaml"
        
        if filepath.endswith('.yaml') or filepath.endswith('.yml'):
            config = ScannerConfig.from_yaml(str(filepath))
        elif filepath.endswith('.json'):
            config = ScannerConfig.from_json(str(filepath))
        else:
            raise ValueError(f"Unsupported config format: {filepath}")
        
        self.configs[name] = config
        if self.current_config is None:
            self.current_config = config
        
        return config
    
    def save_config(self, name: str, config: ScannerConfig = None):
        """Save a configuration"""
        if config is None:
            config = self.current_config
        
        filepath = self.config_dir / f"{name}.yaml"
        config.to_yaml(str(filepath))
        self.configs[name] = config
    
    def get_config(self, name: str = None) -> ScannerConfig:
        """Get configuration by name, or current if None"""
        if name is None:
            return self.current_config
        return self.configs.get(name, self.current_config)
    
    def set_current(self, name: str):
        """Set current configuration"""
        if name in self.configs:
            self.current_config = self.configs[name]
        else:
            raise KeyError(f"Configuration not found: {name}")
    
    def list_configs(self) -> list:
        """List all available configurations"""
        config_files = list(self.config_dir.glob("*.yaml")) + list(self.config_dir.glob("*.json"))
        return [f.stem for f in config_files]


# Default configuration
default_config = ScannerConfig()

# Global config manager
config_manager = ConfigManager()