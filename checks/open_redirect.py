"""Open Redirect Vulnerability Checker - Enhanced with Wordlist"""

import re
import os
import time
from typing import Dict, List
from urllib.parse import urlparse, parse_qs, urlencode
from .base_check import BaseVulnCheck


class OpenRedirectChecker(BaseVulnCheck):
    """Open Redirect vulnerability detector with wordlist support"""
    
    def __init__(self, http_client, config):
        super().__init__(http_client, config)
        
        # Common redirect parameter names
        self.redirect_params = [
            'redirect', 'redirect_to', 'redirect_url', 'redirect_uri',
            'return', 'return_to', 'return_url', 'return_uri',
            'url', 'uri', 'next', 'next_url', 'next_uri',
            'forward', 'forward_to', 'forward_url',
            'go', 'goto', 'target', 'dest', 'destination',
            'r', 'u', 'link', 'href', 'file', 'page'
        ]
        
        # Load payloads from wordlist
        self.payloads = self.load_payloads('open_redirect')
        
        # If wordlist is empty, use default payloads
        if not self.payloads:
            self.payloads = [
                'https://evil.com',
                '//evil.com',
                'http://evil.com',
                r'\/\/evil.com',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                '//evil.com@attacker.com',
                'https://attacker.com\\@evil.com',
                'https://evil.com?',
                'https://evil.com#',
                '/\\evil.com',
                '\\evil.com',
            ]
        
        # External domains to test
        self.test_domains = [
            'evil.com',
            'attacker.com',
            'malicious.com',
            'hacker.com',
            'example.com',
            'google.com',
            'facebook.com'
        ]
    
    @property
    def name(self) -> str:
        return "Open Redirect Checker"
    
    @property
    def severity(self) -> str:
        return "MEDIUM"
    
    def load_payloads(self, payload_type: str) -> List[str]:
        """Load payloads from wordlist file"""
        payloads = []
        
        # Try multiple possible paths
        possible_paths = [
            f"./data/payloads/{payload_type}.txt",
            f"data/payloads/{payload_type}.txt",
            f"../data/payloads/{payload_type}.txt",
            f"payloads/{payload_type}.txt",
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    self.logger.info(f"Loaded {len(payloads)} payloads from {path}")
                    break
                except Exception as e:
                    self.logger.error(f"Error loading payloads from {path}: {e}")
                    continue
        
        return payloads[:100]  # Limit to 100 payloads for performance
    
    def extract_redirect_params(self, url: str) -> List[str]:
        """Extract potential redirect parameters from URL"""
        params = self.extract_parameters(url)
        
        found_params = []
        for param in params.keys():
            param_lower = param.lower()
            for redirect_param in self.redirect_params:
                if redirect_param in param_lower:
                    found_params.append(param)
                    break
        
        return found_params
    
    def extract_parameters(self, url: str) -> Dict[str, List[str]]:
        """Extract all parameters from URL"""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            return query_params
        except:
            return {}
    
    async def test_redirect(self, url: str, param: str, original_value: str, payload: str) -> Dict:
        """Test single parameter for open redirect"""
        try:
            # Build test URL
            parsed = urlparse(url)
            query_dict = parse_qs(parsed.query)
            
            if param in query_dict:
                query_dict[param] = [payload]
            
            new_query = urlencode(query_dict, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            # Make request without following redirects
            response = await self.http_client.request(
                "GET", 
                test_url,
                allow_redirects=False
            )
            
            # Check for redirect
            if response.status in [301, 302, 303, 307, 308]:
                location = response.headers.get('location', '')
                
                # Check if location header contains test domain
                for domain in self.test_domains:
                    if domain in location:
                        return {
                            'type': 'Open Redirect',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'location_header': location,
                            'status_code': response.status,
                            'confidence': self._calculate_confidence(location, payload),
                            'evidence': f"Redirect to {location}"
                        }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Redirect test failed: {e}")
            return None
    
    def _calculate_confidence(self, location: str, payload: str) -> str:
        """Calculate confidence level for open redirect"""
        
        # High confidence if exact payload appears in location
        if payload in location:
            return "HIGH"
        
        # Medium confidence if any test domain appears
        for domain in self.test_domains:
            if domain in location:
                return "MEDIUM"
        
        # Low confidence if location is different from original
        if location and location != '/':
            return "LOW"
        
        return "NONE"
    
    async def run(self, target_url: str) -> Dict:
        """Execute open redirect scan with wordlist"""
        self.logger.info(f"Starting Open Redirect scan for: {target_url}")
        
        start_time = time.time()
        findings = []
        
        # Step 1: Find redirect parameters in URL
        redirect_params = self.extract_redirect_params(target_url)
        
        if not redirect_params:
            self.logger.info("No redirect parameters found in URL")
        else:
            self.logger.info(f"Found {len(redirect_params)} redirect parameter(s)")
            
            # Step 2: Test each parameter
            for param in redirect_params:
                params = self.extract_parameters(target_url)
                original_value = params.get(param, [''])[0]
                
                for payload in self.payloads[:20]:  # Test first 20 payloads
                    self.logger.debug(f"Testing {param} with payload: {payload}")
                    
                    result = await self.test_redirect(
                        target_url, param, original_value, payload
                    )
                    
                    if result:
                        findings.append(result)
                        self.add_finding({
                            "type": "Open Redirect",
                            "url": result['url'],
                            "parameter": result['parameter'],
                            "payload": result['payload'],
                            "severity": self.severity,
                            "confidence": result['confidence'],
                            "description": f"Open redirect vulnerability in {param} parameter redirecting to {result['location_header']}",
                            "recommendation": "Validate and sanitize all redirect URLs, use allowlists for domains",
                            "evidence": result['evidence']
                        })
                        break  # Stop testing this parameter if vulnerability found
        
        # Step 3: Also test common redirect endpoints
        common_paths = [
            '/redirect',
            '/go',
            '/goto',
            '/out',
            '/external',
            '/link'
        ]
        
        base_url = urlparse(target_url)
        for path in common_paths:
            test_url = base_url._replace(path=path).geturl()
            
            try:
                response = await self.http_client.request("GET", test_url)
                if response.status == 200:
                    finding = {
                        'type': 'Potential Redirect Endpoint',
                        'url': test_url,
                        'confidence': 'LOW',
                        'note': f'Common redirect path accessible: {path}'
                    }
                    findings.append(finding)
            except:
                continue
        
        execution_time = time.time() - start_time
        
        return {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "stats": {
                "parameters_tested": len(redirect_params),
                "payloads_tested": min(len(self.payloads), 20) * len(redirect_params),
                "common_paths_tested": len(common_paths),
                "vulnerabilities_found": len(findings),
                "execution_time": execution_time
            }
        }