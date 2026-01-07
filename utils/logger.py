"""
Enhanced Logging System for NullSpecter with file rotation and remote logging
"""

import logging
import sys
import os
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from typing import Optional, Dict, Any
import colorama
import json
from datetime import datetime

colorama.init()

class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_object = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread': record.threadName,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_object['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, 'extra'):
            log_object.update(record.extra)
        
        return json.dumps(log_object, ensure_ascii=False)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors and emojis"""
    
    COLORS = {
        'DEBUG': colorama.Fore.CYAN,
        'INFO': colorama.Fore.GREEN,
        'WARNING': colorama.Fore.YELLOW,
        'ERROR': colorama.Fore.RED,
        'CRITICAL': colorama.Fore.RED + colorama.Style.BRIGHT,
        'RESET': colorama.Style.RESET_ALL
    }
    
    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': 'ℹ️',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '💀',
        'SUCCESS': '✅',
        'SCAN': '🎯',
        'VULN': '🔥'
    }
    
    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname
        emoji = self.EMOJIS.get(levelname, '📝')
        
        # Add emoji to message for certain log types
        if hasattr(record, 'log_type'):
            if record.log_type == 'vulnerability':
                emoji = self.EMOJIS['VULN']
            elif record.log_type == 'scan':
                emoji = self.EMOJIS['SCAN']
            elif record.log_type == 'success':
                emoji = self.EMOJIS['SUCCESS']
        
        # Colorize
        if levelname in self.COLORS:
            colored_level = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
            colored_message = f"{self.COLORS[levelname]}{record.getMessage()}{self.COLORS['RESET']}"
            
            # Format with emoji
            formatted = super().format(record)
            formatted = formatted.replace(levelname, colored_level)
            formatted = formatted.replace(record.getMessage(), colored_message)
            
            # Add emoji at the beginning
            if not formatted.startswith(emoji):
                formatted = f"{emoji} {formatted}"
            
            return formatted
        
        return super().format(record)


class NullSpecterLogger:
    """Advanced logging class for NullSpecter with multiple outputs"""
    
    def __init__(self, name: str = "NullSpecter", config: dict = None):
        self.config = config or {}
        self.logger = logging.getLogger(name)
        
        # Statistics - Initialize BEFORE setup_logger
        self.stats = {
            'debug': 0, 'info': 0, 'warning': 0, 
            'error': 0, 'critical': 0, 'vulnerabilities': 0
        }
        
        self._setup_logger()
        
    def _setup_logger(self):
        """Setup logger with handlers and formatters"""
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Set level
        log_level = getattr(logging, self.config.get('level', 'INFO').upper())
        self.logger.setLevel(log_level)
        
        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = ColoredFormatter(
            '[%(asctime)s] [%(levelname)-8s] %(name)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.INFO)  # Console shows INFO and above
        self.logger.addHandler(console_handler)
        
        # File handler (rotating)
        log_dir = self.config.get('log_dir', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Main log file
        main_log_file = Path(log_dir) / 'nullspecter.log'
        file_handler = RotatingFileHandler(
            main_log_file,
            maxBytes=self.config.get('max_size_mb', 10) * 1024 * 1024,
            backupCount=self.config.get('backup_count', 5),
            encoding='utf-8'
        )
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)  # File contains all levels
        self.logger.addHandler(file_handler)
        
        # JSON log file for structured logging
        json_log_file = Path(log_dir) / 'nullspecter.json.log'
        json_handler = RotatingFileHandler(
            json_log_file,
            maxBytes=self.config.get('max_size_mb', 5) * 1024 * 1024,
            backupCount=self.config.get('backup_count', 3),
            encoding='utf-8'
        )
        json_formatter = JSONFormatter()
        json_handler.setFormatter(json_formatter)
        json_handler.setLevel(logging.INFO)
        self.logger.addHandler(json_handler)
        
        # Error log file (only errors and critical)
        error_log_file = Path(log_dir) / 'nullspecter.error.log'
        error_handler = RotatingFileHandler(
            error_log_file,
            maxBytes=self.config.get('max_size_mb', 2) * 1024 * 1024,
            backupCount=self.config.get('backup_count', 2),
            encoding='utf-8'
        )
        error_formatter = logging.Formatter(
            '%(asctime)s - ERROR - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        error_handler.setFormatter(error_formatter)
        error_handler.setLevel(logging.ERROR)
        self.logger.addHandler(error_handler)
        
        # Don't propagate to root logger
        self.logger.propagate = False
        
        # Log initialization
        self.info(f"Logger initialized with level: {logging.getLevelName(log_level)}")
    
    def _log_with_stats(self, level: str, msg: str, *args, extra: dict = None, **kwargs):
        """Log with statistics tracking"""
        # Update statistics
        if level.lower() in self.stats:
            self.stats[level.lower()] += 1
        
        # Add extra fields
        if extra is None:
            extra = {}
        
        # Log the message
        getattr(self.logger, level.lower())(msg, *args, extra=extra, **kwargs)
    
    def debug(self, msg: str, *args, extra: dict = None, **kwargs):
        """Debug level log"""
        self._log_with_stats('debug', msg, *args, extra=extra, **kwargs)
    
    def info(self, msg: str, *args, extra: dict = None, **kwargs):
        """Info level log"""
        self._log_with_stats('info', msg, *args, extra=extra, **kwargs)
    
    def warning(self, msg: str, *args, extra: dict = None, **kwargs):
        """Warning level log"""
        self._log_with_stats('warning', msg, *args, extra=extra, **kwargs)
    
    def error(self, msg: str, *args, extra: dict = None, **kwargs):
        """Error level log"""
        self._log_with_stats('error', msg, *args, extra=extra, **kwargs)
    
    def critical(self, msg: str, *args, extra: dict = None, **kwargs):
        """Critical level log"""
        self._log_with_stats('critical', msg, *args, extra=extra, **kwargs)
    
    def success(self, msg: str, *args, **kwargs):
        """Success message"""
        extra = {'log_type': 'success'}
        self.info(f"✅ {msg}", *args, extra=extra, **kwargs)
    
    def failure(self, msg: str, *args, **kwargs):
        """Failure message"""
        self.error(f"❌ {msg}", *args, **kwargs)
    
    def scan_start(self, target: str, checks: list = None):
        """Log scan start"""
        extra = {
            'log_type': 'scan',
            'target': target,
            'checks': checks or []
        }
        self.info(f"🎯 Starting scan: {target}", extra=extra)
    
    def scan_end(self, target: str, vulnerabilities: int, duration: float):
        """Log scan end"""
        extra = {
            'log_type': 'scan',
            'target': target,
            'vulnerabilities': vulnerabilities,
            'duration': duration
        }
        
        if vulnerabilities > 0:
            self.critical(f"🚨 Scan complete: Found {vulnerabilities} vulnerability(ies) in {duration:.2f}s", extra=extra)
        else:
            self.success(f"✅ Scan complete: No vulnerabilities found in {duration:.2f}s", extra=extra)
    
    def vuln_found(self, vuln_type: str, url: str, severity: str = "MEDIUM", details: dict = None):
        """Log vulnerability found"""
        severity_icons = {
            "CRITICAL": "💀",
            "HIGH": "🔥",
            "MEDIUM": "⚠️",
            "LOW": "ℹ️"
        }
        
        icon = severity_icons.get(severity.upper(), "⚠️")
        self.stats['vulnerabilities'] += 1
        
        extra = {
            'log_type': 'vulnerability',
            'vulnerability_type': vuln_type,
            'url': url,
            'severity': severity,
            'details': details or {}
        }
        
        self.critical(f"{icon} {vuln_type} found at: {url} [{severity}]", extra=extra)
    
    def request_log(self, method: str, url: str, status: int, duration: float):
        """Log HTTP request"""
        status_color = colorama.Fore.GREEN if status < 400 else colorama.Fore.RED
        reset = colorama.Style.RESET_ALL
        
        extra = {
            'log_type': 'request',
            'method': method,
            'url': url,
            'status': status,
            'duration': duration
        }
        
        self.debug(f"{method} {url} -> {status_color}{status}{reset} ({duration:.3f}s)", extra=extra)
    
    def get_stats(self) -> Dict[str, int]:
        """Get logging statistics"""
        return self.stats.copy()
    
    def get_log_file_paths(self) -> Dict[str, str]:
        """Get paths to log files"""
        log_dir = self.config.get('log_dir', 'logs')
        return {
            'main': str(Path(log_dir) / 'nullspecter.log'),
            'json': str(Path(log_dir) / 'nullspecter.json.log'),
            'error': str(Path(log_dir) / 'nullspecter.error.log')
        }
    
    def clear_logs(self):
        """Clear all log files"""
        log_files = self.get_log_file_paths()
        for file_path in log_files.values():
            if os.path.exists(file_path):
                try:
                    open(file_path, 'w').close()
                    self.info(f"Cleared log file: {file_path}")
                except Exception as e:
                    self.error(f"Failed to clear log file {file_path}: {e}")
        
        # Reset statistics
        self.stats = {k: 0 for k in self.stats}
    
    def get_logger(self) -> logging.Logger:
        """Get the underlying logger object"""
        return self.logger


# Global logger instance with default config
logger = NullSpecterLogger(config={
    'level': 'INFO',
    'log_dir': 'logs',
    'max_size_mb': 10,
    'backup_count': 5
})