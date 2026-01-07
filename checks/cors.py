"""
CORS (Cross-Origin Resource Sharing) Vulnerability Checker
"""

import re
import json
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .base_check import BaseVulnCheck
from utils.helpers import helpers
from utils.logger import logger

class CORSChecker(BaseVulnCheck):
    """CORS misconfiguration detector"""
    
    def __init__(self, http_client, config):
        super().__init__(http_client, config)
        
        # Test origins for CORS
        self.test_origins = [
            'https://evil.com',
            'http://evil.com',
            'https://attacker.com',
            'http://attacker.com',
            'https://example.com',
            'http://example.com',
            'null',
            'https://null',
            'https://target.com.evil.com',
            'https://target-com.evil.com',
        ]
        
        # Test methods
        self.test_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        # Test headers
        self.test_headers = [
            'X-Custom-Header',
            'Authorization',
            'X-API-Key',
            'X-CSRF-Token',
        ]
    
    @property
    def name(self) -> str:
        return "CORS Checker"
    
    @property
    def severity(self) -> str:
        return "MEDIUM"
    
    @property
    def description(self) -> str:
        return "Cross-Origin Resource Sharing - Checks for CORS misconfigurations"
    
    async def test_cors_configuration(self, url: str) -> List[Dict]:
        """Test CORS configuration for vulnerabilities"""
        vulnerabilities = []
        
        # First, make a normal request to check for CORS headers
        normal_response = await self.safe_request("GET", url)
        
        if not normal_response:
            return vulnerabilities
        
        # Check for existing CORS headers
        cors_headers = self.extract_cors_headers(normal_response.headers)
        
        if cors_headers:
            # Analyze existing CORS configuration
            analysis = self.analyze_cors_configuration(cors_headers)
            
            if analysis['vulnerable']:
                vuln = {
                    'type': 'CORS Misconfiguration',
                    'url': url,
                    'headers': cors_headers,
                    'confidence': analysis['confidence'],
                    'description': analysis['description'],
                    'recommendation': 'Implement proper CORS policies: restrict origins, avoid wildcards, validate credentials',
                    'evidence': {
                        'cors_headers': cors_headers,
                        'analysis': analysis
                    }
                }
                
                vulnerabilities.append(vuln)
                self.add_finding(vuln)
        
        # Test with different origins
        origin_vulns = await self.test_origin_validation(url)
        vulnerabilities.extend(origin_vulns)
        
        # Test preflight requests
        preflight_vulns = await self.test_preflight_requests(url)
        vulnerabilities.extend(preflight_vulns)
        
        # Test credentials
        credentials_vulns = await self.test_credentials(url)
        vulnerabilities.extend(credentials_vulns)
        
        return vulnerabilities
    
    def extract_cors_headers(self, headers: Dict) -> Dict:
        """Extract CORS-related headers"""
        cors_headers = {}
        
        cors_header_names = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Credentials',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Access-Control-Expose-Headers',
            'Access-Control-Max-Age',
        ]
        
        for header in cors_header_names:
            if header in headers:
                cors_headers[header] = headers[header]
        
        return cors_headers
    
    def analyze_cors_configuration(self, cors_headers: Dict) -> Dict:
        """Analyze CORS configuration for vulnerabilities"""
        analysis = {
            'vulnerable': False,
            'confidence': 'NONE',
            'description': '',
            'issues': []
        }
        
        # Check for wildcard origin with credentials
        if 'Access-Control-Allow-Origin' in cors_headers:
            acao = cors_headers['Access-Control-Allow-Origin']
            
            if acao == '*':
                analysis['issues'].append('Wildcard origin (*) allowed')
                analysis['confidence'] = 'MEDIUM'
                
                # Check if credentials are allowed with wildcard
                if cors_headers.get('Access-Control-Allow-Credentials', '').lower() == 'true':
                    analysis['issues'].append('Credentials allowed with wildcard origin')
                    analysis['confidence'] = 'HIGH'
                    analysis['description'] = 'Wildcard origin with credentials is a critical vulnerability'
                    analysis['vulnerable'] = True
            
            # Check for null origin
            elif acao == 'null':
                analysis['issues'].append('Null origin allowed')
                analysis['confidence'] = 'MEDIUM'
                analysis['vulnerable'] = True
            
            # Check for overly permissive regex patterns
            elif re.search(r'\.\*|\*\.|\^.*\$', acao):
                analysis['issues'].append('Regex pattern in origin may be too permissive')
                analysis['confidence'] = 'LOW'
        
        # Check for overly permissive methods
        if 'Access-Control-Allow-Methods' in cors_headers:
            methods = cors_headers['Access-Control-Allow-Methods']
            if methods == '*' or 'DELETE' in methods or 'PUT' in methods:
                analysis['issues'].append('Potentially dangerous methods allowed')
                if analysis['confidence'] == 'NONE':
                    analysis['confidence'] = 'LOW'
        
        # Check for overly permissive headers
        if 'Access-Control-Allow-Headers' in cors_headers:
            headers = cors_headers['Access-Control-Allow-Headers']
            if headers == '*':
                analysis['issues'].append('Wildcard allowed headers')
                if analysis['confidence'] == 'NONE':
                    analysis['confidence'] = 'LOW'
        
        # Determine if vulnerable
        if analysis['confidence'] in ['MEDIUM', 'HIGH']:
            analysis['vulnerable'] = True
        elif analysis['confidence'] == 'LOW' and len(analysis['issues']) >= 2:
            analysis['vulnerable'] = True
        
        if not analysis['description'] and analysis['issues']:
            analysis['description'] = 'CORS misconfiguration: ' + ', '.join(analysis['issues'])
        
        return analysis
    
    async def test_origin_validation(self, url: str) -> List[Dict]:
        """Test origin validation for weaknesses"""
        vulnerabilities = []
        
        for origin in self.test_origins:
            try:
                headers = {'Origin': origin}
                response = await self.safe_request("GET", url, headers=headers)
                
                if not response:
                    continue
                
                # Check for reflected origin
                if 'Access-Control-Allow-Origin' in response.headers:
                    acao = response.headers['Access-Control-Allow-Origin']
                    
                    if acao == origin or acao == '*':
                        # Check if this is a vulnerable configuration
                        vuln_analysis = self.analyze_origin_reflection(origin, acao, response.headers)
                        
                        if vuln_analysis['vulnerable']:
                            vuln = {
                                'type': 'CORS Origin Reflection',
                                'url': url,
                                'tested_origin': origin,
                                'allowed_origin': acao,
                                'confidence': vuln_analysis['confidence'],
                                'description': vuln_analysis['description'],
                                'recommendation': 'Implement strict origin validation, do not reflect arbitrary origins',
                                'evidence': {
                                    'tested_origin': origin,
                                    'allowed_origin': acao,
                                    'headers': dict(response.headers),
                                    'analysis': vuln_analysis
                                }
                            }
                            
                            vulnerabilities.append(vuln)
                            self.add_finding(vuln)
            
            except Exception as e:
                self.logger.error(f"Origin validation test failed for {origin}: {e}")
                continue
        
        return vulnerabilities
    
    def analyze_origin_reflection(self, tested_origin: str, allowed_origin: str, headers: Dict) -> Dict:
        """Analyze origin reflection vulnerability"""
        analysis = {
            'vulnerable': False,
            'confidence': 'NONE',
            'description': '',
            'issues': []
        }
        
        # Check for exact reflection
        if tested_origin == allowed_origin:
            analysis['issues'].append('Origin exactly reflected')
            analysis['confidence'] = 'HIGH'
            analysis['vulnerable'] = True
        
        # Check for wildcard
        elif allowed_origin == '*':
            analysis['issues'].append('Wildcard origin')
            analysis['confidence'] = 'MEDIUM'
            analysis['vulnerable'] = True
        
        # Check for null
        elif allowed_origin == 'null':
            analysis['issues'].append('Null origin')
            analysis['confidence'] = 'MEDIUM'
            analysis['vulnerable'] = True
        
        # Check for credentials with reflected origin
        if headers.get('Access-Control-Allow-Credentials', '').lower() == 'true':
            analysis['issues'].append('Credentials allowed')
            if analysis['confidence'] in ['MEDIUM', 'LOW']:
                analysis['confidence'] = 'HIGH'
            analysis['vulnerable'] = True
        
        if analysis['issues']:
            analysis['description'] = 'CORS origin validation issue: ' + ', '.join(analysis['issues'])
        
        return analysis
    
    async def test_preflight_requests(self, url: str) -> List[Dict]:
        """Test OPTIONS preflight requests"""
        vulnerabilities = []
        
        for method in self.test_methods:
            for header in self.test_headers:
                try:
                    # Create preflight request
                    headers = {
                        'Origin': 'https://evil.com',
                        'Access-Control-Request-Method': method,
                        'Access-Control-Request-Headers': header,
                    }
                    
                    response = await self.safe_request("OPTIONS", url, headers=headers)
                    
                    if not response:
                        continue
                    
                    # Analyze preflight response
                    analysis = self.analyze_preflight_response(response.headers, method, header)
                    
                    if analysis['vulnerable']:
                        vuln = {
                            'type': 'CORS Preflight Misconfiguration',
                            'url': url,
                            'method': method,
                            'header': header,
                            'confidence': analysis['confidence'],
                            'description': analysis['description'],
                            'recommendation': 'Validate preflight requests properly, restrict methods and headers',
                            'evidence': {
                                'tested_method': method,
                                'tested_header': header,
                                'headers': dict(response.headers),
                                'analysis': analysis
                            }
                        }
                        
                        vulnerabilities.append(vuln)
                        self.add_finding(vuln)
                
                except Exception as e:
                    self.logger.error(f"Preflight test failed for {method} {header}: {e}")
                    continue
        
        return vulnerabilities
    
    def analyze_preflight_response(self, headers: Dict, tested_method: str, tested_header: str) -> Dict:
        """Analyze preflight response for vulnerabilities"""
        analysis = {
            'vulnerable': False,
            'confidence': 'NONE',
            'description': '',
            'issues': []
        }
        
        # Check for method allowance
        if 'Access-Control-Allow-Methods' in headers:
            allowed_methods = headers['Access-Control-Allow-Methods']
            
            if allowed_methods == '*' or tested_method in allowed_methods:
                analysis['issues'].append(f'Method {tested_method} allowed')
                
                # Check if it's a dangerous method
                if tested_method in ['DELETE', 'PUT', 'PATCH']:
                    analysis['confidence'] = 'MEDIUM'
                else:
                    analysis['confidence'] = 'LOW'
        
        # Check for header allowance
        if 'Access-Control-Allow-Headers' in headers:
            allowed_headers = headers['Access-Control-Allow-Headers']
            
            if allowed_headers == '*' or tested_header in allowed_headers:
                analysis['issues'].append(f'Header {tested_header} allowed')
                if analysis['confidence'] == 'NONE':
                    analysis['confidence'] = 'LOW'
        
        # Check for origin reflection in preflight
        if 'Access-Control-Allow-Origin' in headers:
            acao = headers['Access-Control-Allow-Origin']
            
            if acao == 'https://evil.com' or acao == '*':
                analysis['issues'].append('Origin reflected or wildcard in preflight')
                if analysis['confidence'] in ['NONE', 'LOW']:
                    analysis['confidence'] = 'MEDIUM'
        
        # Determine if vulnerable
        if analysis['confidence'] in ['MEDIUM', 'HIGH']:
            analysis['vulnerable'] = True
        elif analysis['confidence'] == 'LOW' and len(analysis['issues']) >= 2:
            analysis['vulnerable'] = True
        
        if analysis['issues']:
            analysis['description'] = 'Preflight misconfiguration: ' + ', '.join(analysis['issues'])
        
        return analysis
    
    async def test_credentials(self, url: str) -> List[Dict]:
        """Test CORS with credentials"""
        vulnerabilities = []
        
        try:
            # Test with credentials flag
            headers = {'Origin': 'https://evil.com'}
            
            # First without credentials
            response1 = await self.safe_request("GET", url, headers=headers)
            
            # Then with credentials simulation
            response2 = await self.safe_request("GET", url, headers=headers)
            
            if not response1 or not response2:
                return vulnerabilities
            
            # Analyze credential handling
            analysis = self.analyze_credential_handling(response1.headers, response2.headers)
            
            if analysis['vulnerable']:
                vuln = {
                    'type': 'CORS Credential Handling Issue',
                    'url': url,
                    'confidence': analysis['confidence'],
                    'description': analysis['description'],
                    'recommendation': 'Be cautious with Access-Control-Allow-Credentials, ensure proper origin validation',
                    'evidence': {
                        'without_credentials': dict(response1.headers),
                        'with_credentials': dict(response2.headers),
                        'analysis': analysis
                    }
                }
                
                vulnerabilities.append(vuln)
                self.add_finding(vuln)
        
        except Exception as e:
            self.logger.error(f"Credential test failed: {e}")
        
        return vulnerabilities
    
    def analyze_credential_handling(self, headers1: Dict, headers2: Dict) -> Dict:
        """Analyze credential handling in CORS"""
        analysis = {
            'vulnerable': False,
            'confidence': 'NONE',
            'description': '',
            'issues': []
        }
        
        # Check if credentials are allowed
        acac1 = headers1.get('Access-Control-Allow-Credentials', '').lower()
        acac2 = headers2.get('Access-Control-Allow-Credentials', '').lower()
        
        if acac1 == 'true' or acac2 == 'true':
            analysis['issues'].append('Credentials allowed')
            analysis['confidence'] = 'MEDIUM'
            
            # Check if origin is properly restricted when credentials are allowed
            acao1 = headers1.get('Access-Control-Allow-Origin', '')
            acao2 = headers2.get('Access-Control-Allow-Origin', '')
            
            if acao1 == '*' or acao2 == '*':
                analysis['issues'].append('Wildcard origin with credentials')
                analysis['confidence'] = 'HIGH'
                analysis['vulnerable'] = True
            
            elif acao1 == 'null' or acao2 == 'null':
                analysis['issues'].append('Null origin with credentials')
                analysis['confidence'] = 'HIGH'
                analysis['vulnerable'] = True
        
        if analysis['issues']:
            analysis['description'] = 'CORS credential issue: ' + ', '.join(analysis['issues'])
        
        return analysis
    
    async def run(self, target_url: str) -> Dict:
        """Execute CORS scan"""
        self.logger.info(f"Starting CORS scan for: {target_url}")
        start_time = time.time()
        
        # Test CORS configuration
        findings = await self.test_cors_configuration(target_url)
        
        execution_time = time.time() - start_time
        
        self.metrics['test_cases_run'] = (
            len(self.test_origins) + 
            len(self.test_methods) * len(self.test_headers) + 
            1  # credential test
        )
        
        return {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "stats": {
                "origins_tested": len(self.test_origins),
                "preflight_tests": len(self.test_methods) * len(self.test_headers),
                "vulnerabilities_found": len(findings),
                "execution_time": execution_time
            }
        }