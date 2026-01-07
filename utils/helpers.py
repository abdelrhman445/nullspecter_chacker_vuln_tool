"""
Enhanced Utility functions for NullSpecter
Final Version - 2026 (Patched)
"""

import re
import hashlib
import random
import string
import json
import yaml
import math
import ipaddress
import base64
import zlib
import html
from typing import Dict, List, Any, Optional, Union
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from datetime import datetime

class Helpers:
    """Collection of helper utilities for security scanning"""
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
            
            # Check for common schemes
            if result.scheme not in ['http', 'https', 'ftp', 'ws', 'wss']:
                return False
            
            return True
        except:
            return False
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL by removing fragments, sorting params, and standardizing"""
        try:
            parsed = urlparse(url)
            
            # Ensure scheme and netloc
            if not parsed.scheme:
                parsed = parsed._replace(scheme='http')
            
            # Remove fragment
            parsed = parsed._replace(fragment="")
            
            # Sort query parameters
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                sorted_params = sorted(params.items())
                query = urlencode(sorted_params, doseq=True)
                parsed = parsed._replace(query=query)
            
            # Normalize path
            path = parsed.path
            if not path:
                path = '/'
            elif not path.startswith('/'):
                path = '/' + path
            
            parsed = parsed._replace(path=path)
            
            # Lowercase hostname
            parsed = parsed._replace(netloc=parsed.netloc.lower())
            
            return parsed.geturl()
        except:
            return url
    
    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            return urlparse(url).netloc.split(':')[0]  # Remove port
        except:
            return ""
    
    @staticmethod
    def extract_params(url: str) -> Dict[str, List[str]]:
        """Extract parameters from URL with deep parsing"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            # Also check for parameters in fragment
            if parsed.fragment and '?' in parsed.fragment:
                fragment_params = parse_qs(parsed.fragment.split('?')[1], keep_blank_values=True)
                params.update(fragment_params)
            
            return params
        except:
            return {}
    
    @staticmethod
    def build_url(base: str, params: Dict[str, Any]) -> str:
        """Build URL with parameters, handling arrays and special characters"""
        parsed = urlparse(base)
        
        # Encode parameters properly
        encoded_params = []
        for key, value in params.items():
            if isinstance(value, list):
                for v in value:
                    encoded_params.append((f"{key}[]", str(v)))
            else:
                encoded_params.append((key, str(value)))
        
        query = urlencode(encoded_params, doseq=True, quote_via=quote)
        return parsed._replace(query=query).geturl()
    
    @staticmethod
    def generate_random_string(length: int = 10, charset: str = None) -> str:
        """Generate random string with optional charset"""
        if charset is None:
            charset = string.ascii_letters + string.digits + "_-."
        
        return ''.join(random.choice(charset) for _ in range(length))
    
    @staticmethod
    def generate_test_payloads(base: str) -> List[str]:
        """Generate test payloads based on base string"""
        payloads = [
            base,
            base + "'",
            base + '"',
            base + "`",
            base + "--",
            base + "#",
            base + "/*",
            base + " OR '1'='1",
            base + "' OR '1'='1",      # <--- Added missing payload for unit test
            base + "' OR '1'='1'--",
            base + "' UNION SELECT NULL--",
            base + "<script>alert(1)</script>",
            base + "${7*7}",
            base + "{{7*7}}",
            base + "|ls",
            base + ";ls",
            base + "||ls",
            base + "&&ls",
            base + "\nls",
            base + "$(ls)",
            base + "`ls`",
        ]
        
        return payloads
    
    @staticmethod
    def md5_hash(data: str) -> str:
        """Generate MD5 hash"""
        return hashlib.md5(data.encode()).hexdigest()
    
    @staticmethod
    def sha256_hash(data: str) -> str:
        """Generate SHA256 hash"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def is_ip_address(ip: str) -> bool:
        """Check if string is valid IP address (IPv4 or IPv6)"""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extract email addresses from text"""
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return re.findall(pattern, text)
    
    @staticmethod
    def extract_phone_numbers(text: str) -> List[str]:
        """Extract phone numbers from text"""
        pattern = r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        return re.findall(pattern, text)
    
    @staticmethod
    def extract_secrets(text: str) -> List[Dict]:
        """Extract potential secrets from text with Enhanced Patterns"""
        secrets = []
        
        # Enhanced patterns for 2026
        patterns = {
            'google_api': r'AIza[0-9A-Za-z\\-_]{35}',
            'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----',
            'aws_access_key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'jwt_token': r'eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}',
            'stripe_key': r'(?:sk_live_|pk_live_)[0-9a-zA-Z]{24}',
            'shodan_api': r'[A-Za-z0-9]{32}', 
            'generic_api': r'(?i)(api[_-]?key|auth[_-]?token|access[_-]?token)[\s:=]+["\']?([a-zA-Z0-9_\-]{32,})["\']?',
        }
        
        for secret_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            for match in matches:
                # Handle tuple matches from capturing groups
                if isinstance(match, tuple):
                    secret_value = max(match, key=len)
                else:
                    secret_value = match
                
                # Skip short false positives
                if len(secret_value) < 8: continue

                # Get context (20 chars before/after)
                start_idx = text.find(secret_value)
                context = ""
                if start_idx != -1:
                    start_ctx = max(0, start_idx - 20)
                    end_ctx = min(len(text), start_idx + len(secret_value) + 20)
                    context = text[start_ctx:end_ctx]

                secrets.append({
                    'type': secret_type,
                    'value': secret_value,
                    'context': context
                })
        
        return secrets
    
    @staticmethod
    def json_pretty(data: Any) -> str:
        """Pretty print JSON with sorting"""
        return json.dumps(data, indent=2, sort_keys=True, default=str)
    
    @staticmethod
    def safe_json_parse(data: str) -> Optional[Dict]:
        """Safely parse JSON, returns None on error"""
        try:
            return json.loads(data)
        except:
            return None
    
    @staticmethod
    def load_yaml(filepath: str) -> Dict:
        """Load YAML configuration file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Error loading YAML: {e}")
            return {}
    
    @staticmethod
    def save_yaml(data: Dict, filepath: str):
        """Save data to YAML file"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
        except Exception as e:
            print(f"Error saving YAML: {e}")
    
    @staticmethod
    def load_json(filepath: str) -> Dict:
        """Load JSON file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f) or {}
        except:
            return {}
    
    @staticmethod
    def save_json(data: Any, filepath: str):
        """Save data to JSON file"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            print(f"Error saving JSON: {e}")
    
    @staticmethod
    def get_timestamp(format_str: str = "%Y%m%d_%H%M%S") -> str:
        """Get current timestamp"""
        return datetime.now().strftime(format_str)
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in seconds to human readable"""
        if seconds < 1:
            return f"{seconds*1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.2f}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            remaining = seconds % 60
            return f"{minutes}m {remaining:.0f}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for char in set(data):
            p_x = data.count(char) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        
        return entropy
    
    @staticmethod
    def detect_encoding(data: bytes) -> str:
        """Detect encoding of bytes"""
        try:
            import chardet
            result = chardet.detect(data)
            return result['encoding'] or 'utf-8'
        except:
            return 'utf-8'
    
    @staticmethod
    def get_file_extension(url: str) -> str:
        """Get file extension from URL"""
        path = urlparse(url).path
        if '.' in path:
            ext = path.split('.')[-1].lower()
            # Remove query parameters from extension
            if '?' in ext:
                ext = ext.split('?')[0]
            return ext
        return ''
    
    @staticmethod
    def is_safe_path(path: str) -> bool:
        """Check if path is safe (no directory traversal)"""
        dangerous_patterns = [
            '..', '../', '/..', '\\..', '~/', '~\\',
            '://', 'javascript:', 'data:', 'vbscript:'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in path:
                return False
        
        return True
    
    @staticmethod
    def chunk_list(lst: List, size: int) -> List[List]:
        """Split list into chunks"""
        return [lst[i:i + size] for i in range(0, len(lst), size)]
    
    @staticmethod
    def flatten_list(nested_list: List[List]) -> List:
        """Flatten nested list"""
        return [item for sublist in nested_list for item in sublist]
    
    @staticmethod
    def html_encode(text: str) -> str:
        """HTML encode text"""
        return html.escape(text)
    
    @staticmethod
    def base64_encode(data: str) -> str:
        """Base64 encode string"""
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def base64_decode(data: str) -> str:
        """Base64 decode string"""
        try:
            return base64.b64decode(data.encode()).decode()
        except:
            return data
    
    @staticmethod
    def compress(data: str) -> bytes:
        """Compress string using zlib"""
        return zlib.compress(data.encode())
    
    @staticmethod
    def decompress(data: bytes) -> str:
        """Decompress bytes using zlib"""
        return zlib.decompress(data).decode()
    
    @staticmethod
    def generate_fingerprint(data: str) -> Dict:
        """Generate fingerprint of data"""
        return {
            'md5': Helpers.md5_hash(data),
            'sha256': Helpers.sha256_hash(data),
            'length': len(data),
            'entropy': Helpers.calculate_entropy(data),
            'lines': len(data.splitlines()),
            'words': len(data.split())
        }
    
    @staticmethod
    def parse_http_headers(headers_str: str) -> Dict[str, str]:
        """Parse HTTP headers string to dictionary"""
        headers = {}
        for line in headers_str.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return 1 <= port <= 65535
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False

# Global helper instance
helpers = Helpers()