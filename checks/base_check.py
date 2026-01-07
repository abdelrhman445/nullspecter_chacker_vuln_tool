"""
Base class for all vulnerability checks
Ensures consistent interface, logging, payload loading, and safe requests.
Location: checks/base_check.py
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union
import time
from pathlib import Path
import asyncio

# استيراد اللوجر
try:
    from utils.logger import NullSpecterLogger
except ImportError:
    # Fallback if utils not found immediately (setup issues)
    import logging
    NullSpecterLogger = logging.getLogger

class BaseVulnCheck(ABC):
    """Abstract base class for all vulnerability checks"""
    
    def __init__(self, http_client, config: Dict[str, Any] = None):
        """
        Initialize the base check.
        :param http_client: The async HTTP client instance
        :param config: Configuration dictionary or object
        """
        self.http_client = http_client
        self.config = config or {}
        
        # Dynamic logger name based on class name (e.g., check.SQLIChecker)
        self.logger = NullSpecterLogger(name=f"check.{self.__class__.__name__}")
        
        self.findings = []
        self.metrics = {
            'requests_made': 0,
            'test_cases_run': 0,
            'start_time': time.time(),
            'findings_count': 0
        }
        
    @abstractmethod
    async def run(self, target_url: str) -> Dict:
        """Main method to run the check (Must be implemented by subclasses)"""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the check"""
        pass
    
    @property
    @abstractmethod
    def severity(self) -> str:
        """Severity level (LOW/MEDIUM/HIGH/CRITICAL)"""
        pass
    
    # -------------------------------------------------------------------------
    # 1. HTTP Request Helpers (The Fix for 'object has no attribute safe_request')
    # -------------------------------------------------------------------------
    
    async def safe_request(self, method: str, url: str, **kwargs):
        """
        Wrapper to send HTTP requests safely via the http_client.
        Handles exceptions and ensures metrics are updated.
        """
        try:
            # Pass request to the actual http_client
            response = await self.http_client.request(method, url, **kwargs)
            self.metrics['requests_made'] += 1
            return response
        except Exception as e:
            # Log debug only to avoid spamming console with connection errors
            self.logger.debug(f"Request failed to {url}: {e}")
            return None

    async def request(self, method: str, url: str, **kwargs):
        """Alias for safe_request for compatibility"""
        return await self.safe_request(method, url, **kwargs)

    # -------------------------------------------------------------------------
    # 2. Result & Logging Helpers
    # -------------------------------------------------------------------------

    def add_finding(self, finding: Dict):
        """Add a finding to the results and log it immediately"""
        self.findings.append(finding)
        self.metrics['findings_count'] += 1
        
        # Log immediately with colors
        severity = finding.get('severity', self.severity).upper()
        url = finding.get('url', 'unknown')
        type_ = finding.get('type', self.name)
        
        if severity == 'CRITICAL':
            self.logger.critical(f"🔥 {type_} found at: {url}")
        elif severity == 'HIGH':
            self.logger.error(f"🚨 {type_} found at: {url}")
        elif severity == 'MEDIUM':
            self.logger.warning(f"⚠️ {type_} found at: {url}")
        else:
            self.logger.info(f"ℹ️ {type_} found at: {url}")

    # -------------------------------------------------------------------------
    # 3. Payload Management (The Fix for 'object has no attribute load_payloads')
    # -------------------------------------------------------------------------

    def load_payloads(self, filename_no_ext: str) -> List[str]:
        """
        Load payloads from file or return empty list.
        Looks in ./data/payloads/{name}.txt
        
        This method is smart enough to find the file whether you run from 
        the root directory or specifically inside the checks directory.
        """
        filename = f"{filename_no_ext}.txt"
        
        # Define search paths (Robust lookup)
        search_paths = [
            # 1. Try relative to current working directory (e.g. running main.py)
            Path(f"data/payloads/{filename}"), 
            # 2. Try relative to this file's location (checks/base_check.py -> ../../data/payloads)
            Path(__file__).resolve().parent.parent / "data" / "payloads" / filename,
        ]
        
        for path in search_paths:
            if path.exists():
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    
                    if payloads:
                        self.logger.info(f"Loaded {len(payloads)} payloads from {path.name}")
                        return payloads
                except Exception as e:
                    self.logger.error(f"Error loading payloads from {path}: {e}")
        
        # Log debug if not found (Checkers should implement fallbacks)
        self.logger.debug(f"No external payload file found for {filename}. Using built-in/generated payloads.")
        return []

    # -------------------------------------------------------------------------
    # 4. Analysis Helpers
    # -------------------------------------------------------------------------

    def analyze_response_for_errors(self, response, original_response=None) -> Dict:
        """
        Generic analysis for common error patterns in HTTP responses.
        Useful for Error-Based SQLi, LFI, etc.
        """
        analysis = {
            'vulnerable': False,
            'confidence': 'NONE',
            'indicators': []
        }
        
        # Common error patterns dictionary
        error_indicators = [
            ('SQL Injection', [
                'SQL syntax', 'mysql_', 'ORA-', 'PostgreSQL', 'SQLite', 
                'syntax error', 'ODBC', 'JDBC', 'Unclosed quotation mark'
            ]),
            ('XSS', [
                '<script>alert', 'javascript:alert', 'onerror=', 
                'onload=', 'onmouseover='
            ]),
            ('File Inclusion', [
                'root:', 'boot.ini', '[extensions]', 'Warning: include(', 
                'failed to open stream'
            ]),
            ('Command Injection', [
                'sh:', 'bash:', 'cmd.exe', '/bin/sh', 'uid='
            ])
        ]
        
        if hasattr(response, 'text'):
            text = response.text.lower()
            for vuln_type, patterns in error_indicators:
                for pattern in patterns:
                    if pattern.lower() in text:
                        analysis['indicators'].append(f"{vuln_type} pattern: {pattern}")
                        analysis['confidence'] = 'MEDIUM'
                        analysis['vulnerable'] = True
        
        # Basic check for reflection if original response provided (for XSS mostly)
        if original_response and hasattr(response, 'text'):
            # This is generic; checks usually implement more specific logic
            pass
        
        return analysis
    
    def cleanup(self):
        """Cleanup resources and finalize metrics"""
        # self.findings.clear() # Optional: keep findings for report generation
        self.metrics['end_time'] = time.time()