"""
IDOR (Insecure Direct Object Reference) Detection Module
Behavior-based detection with multiple attack vectors
"""
import re
import json
import asyncio
import time  # ✅ تم الإضافة
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode, quote

from .base_check import BaseVulnCheck
from utils.helpers import helpers

@dataclass
class IDORTest:
    """IDOR Test Case"""
    url: str
    method: str
    params: Dict
    headers: Dict
    original_response: str
    test_type: str


class IDORChecker(BaseVulnCheck):
    """
    Advanced IDOR Detector with:
    1. Sequential ID Testing
    2. UUID Guessing
    3. Horizontal Escalation
    4. Batch Enumeration
    5. Response Diff Analysis
    """
    
    def __init__(self, http_client, config):
        super().__init__(http_client, config)
        
        # ID Patterns to detect
        self.id_patterns = [
            (r'\b\d{1,8}\b', 'numeric'),  # Numeric IDs
            (r'[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}', 'uuid'),  # UUID partial
            (r'[0-9a-f]{24}', 'mongodb'),  # MongoDB ObjectId
            (r'usr_[A-Za-z0-9]{10}', 'custom'),  # Custom patterns
            (r'tkn_[A-Za-z0-9]{16}', 'custom'),
            (r'id-[A-Za-z0-9]{12}', 'custom'),
        ]
        
        self.test_results = []
        
    @property
    def name(self) -> str:
        return "IDOR Checker"
    
    @property
    def severity(self) -> str:
        return "HIGH"
    
    @property
    def description(self) -> str:
        return "Insecure Direct Object Reference - Checks for unauthorized access to resources"
    
    def extract_ids_from_url(self, url: str) -> List[Tuple[str, str, str]]:
        """Extract potential IDs from URL path and parameters"""
        ids = []
        
        # Parse URL
        parsed = urlparse(url)
        
        # Check path segments
        path_segments = parsed.path.strip('/').split('/')
        for i, segment in enumerate(path_segments):
            for pattern, id_type in self.id_patterns:
                if re.match(pattern, segment):
                    ids.append((f"path_{i}", segment, id_type))
        
        # Check query parameters
        query_params = parse_qs(parsed.query)
        for param, values in query_params.items():
            for value in values:
                for pattern, id_type in self.id_patterns:
                    if re.match(pattern, value):
                        ids.append((param, value, id_type))
        
        # Check fragment
        if parsed.fragment:
            for pattern, id_type in self.id_patterns:
                if re.match(pattern, parsed.fragment):
                    ids.append(('fragment', parsed.fragment, id_type))
        
        return ids
    
    def generate_test_values(self, original_id: str, id_type: str) -> List[str]:
        """Generate test values based on ID type"""
        tests = []
        
        if id_type == 'numeric':
            try:
                num_id = int(original_id)
                tests.extend([
                    str(num_id + 1),      # Next sequential
                    str(num_id - 1),      # Previous sequential
                    str(num_id + 100),    # Far offset
                    "0",                  # Zero
                    "-1",                 # Negative
                    str(num_id * 2),      # Double
                    "999999",             # Large number
                    str(num_id),          # Same (for comparison)
                ])
            except:
                pass
        
        elif id_type == 'uuid':
            import uuid
            tests.append(str(uuid.uuid4()))
            
            if '-' in original_id:
                parts = original_id.split('-')
                if len(parts) == 5:
                    # Keep same version/variant
                    tests.append(f"{parts[0]}-{parts[1]}-{parts[2]}-{uuid.uuid4().hex[16:20]}-{uuid.uuid4().hex[20:]}")
            
            # Test with different cases
            tests.append(original_id.upper())
            tests.append(original_id.lower())
        
        elif id_type == 'mongodb':
            import random
            import string
            # Generate similar ObjectId
            tests.append(''.join(random.choices(string.hexdigits.lower(), k=24)))
        
        elif id_type == 'custom':
            # Try common variations
            tests.append(original_id.upper())
            tests.append(original_id.lower())
            tests.append(original_id + '1')
            tests.append(original_id[:-1] if len(original_id) > 1 else original_id)
        
        # Always test with empty string
        tests.append("")
        
        return tests
    
    async def test_parameter(self, original_url: str, param_name: str, 
                            original_value: str, param_type: str, test_values: List[str]) -> List[Dict]:
        """Test single parameter for IDOR"""
        vulnerabilities = []
        
        # Get original response for comparison
        try:
            original_response = await self.safe_request(
                method="GET",
                url=original_url
            )
            
            if original_response and original_response.ok:
                original_text = original_response.text
                original_status = original_response.status
                original_length = len(original_text)
            else:
                original_text = ""
                original_status = 0
                original_length = 0
        except:
            original_text = ""
            original_status = 0
            original_length = 0
        
        for test_value in test_values[:8]:  # Limit to 8 tests per param
            try:
                # Replace ID in URL
                test_url = self.replace_id_in_url(original_url, param_name, original_value, test_value)
                
                if test_url == original_url:
                    continue
                
                # Make request with same headers/cookies
                response = await self.safe_request(
                    method="GET",
                    url=test_url
                )
                
                if not response:
                    continue
                
                # Analyze response
                analysis = self.analyze_idor_response(
                    original_response={
                        'status': original_status,
                        'length': original_length,
                        'content': original_text
                    },
                    test_response={
                        'status': response.status,
                        'length': len(response.text) if hasattr(response, 'text') else 0,
                        'content': response.text if hasattr(response, 'text') else ''
                    }
                )
                
                if analysis['vulnerable']:
                    vuln = {
                        "type": "IDOR",
                        "url": test_url,
                        "parameter": param_name,
                        "parameter_type": param_type,
                        "original_value": original_value,
                        "test_value": test_value,
                        "status_code": response.status,
                        "response_length": len(response.text) if hasattr(response, 'text') else 0,
                        "confidence": analysis['confidence'],
                        "description": f"IDOR vulnerability found in {param_name} parameter",
                        "recommendation": "Implement proper access control checks and use indirect object references",
                        "evidence": {
                            "original_url": original_url,
                            "test_url": test_url,
                            "analysis": analysis
                        }
                    }
                    
                    vulnerabilities.append(vuln)
                    
                    # Log finding
                    self.add_finding(vuln)
                    
            except Exception as e:
                self.logger.error(f"Error testing {param_name}: {e}")
                continue
        
        return vulnerabilities
    
    def replace_id_in_url(self, url: str, param_name: str, 
                         old_value: str, new_value: str) -> str:
        """Replace ID value in URL while maintaining structure"""
        # If parameter is in path segment
        if param_name.startswith("path_"):
            segments = url.split('/')
            for i, segment in enumerate(segments):
                if segment == old_value:
                    segments[i] = new_value
                    break
            return '/'.join(segments)
        
        # If parameter is in query string
        else:
            parsed = urlparse(url)
            query_dict = parse_qs(parsed.query, keep_blank_values=True)
            
            if param_name in query_dict:
                # Replace all occurrences of the value
                new_values = []
                for val in query_dict[param_name]:
                    if val == old_value:
                        new_values.append(new_value)
                    else:
                        new_values.append(val)
                query_dict[param_name] = new_values
            
            # Rebuild URL
            new_query = urlencode(query_dict, doseq=True)
            return parsed._replace(query=new_query).geturl()
    
    def analyze_idor_response(self, original_response: Dict, test_response: Dict) -> Dict:
        """Analyze if response indicates IDOR vulnerability"""
        analysis = {
            'vulnerable': False,
            'confidence': 'NONE',
            'indicators': []
        }
        
        # Check for successful access (2xx status)
        if 200 <= test_response['status'] < 300:
            analysis['indicators'].append('Successful access (2xx)')
            analysis['confidence'] = 'LOW'
            
            # Check if content differs from original
            if original_response['content'] and test_response['content']:
                if original_response['content'] != test_response['content']:
                    analysis['indicators'].append('Different content')
                    analysis['confidence'] = 'MEDIUM'
                    
                    # Check for sensitive data
                    if self.contains_sensitive_data(test_response['content']):
                        analysis['indicators'].append('Sensitive data found')
                        analysis['confidence'] = 'HIGH'
        
        # Check for authorization bypass (access despite 403/401 on original)
        elif original_response['status'] in [401, 403] and test_response['status'] not in [401, 403]:
            analysis['indicators'].append('Authorization bypass')
            analysis['confidence'] = 'HIGH'
        
        # Check for information leakage (different error messages)
        elif (original_response['status'] >= 400 and test_response['status'] >= 400 and
              original_response['content'] != test_response['content']):
            analysis['indicators'].append('Different error responses')
            analysis['confidence'] = 'LOW'
        
        # Check for user-specific data patterns
        if self.contains_user_data(test_response['content']):
            analysis['indicators'].append('User data detected')
            analysis['confidence'] = 'HIGH' if analysis['confidence'] != 'HIGH' else 'HIGH'
        
        # Determine if vulnerable
        if analysis['confidence'] in ['MEDIUM', 'HIGH']:
            analysis['vulnerable'] = True
        elif analysis['confidence'] == 'LOW' and len(analysis['indicators']) >= 2:
            analysis['vulnerable'] = True
        
        return analysis
    
    def contains_sensitive_data(self, content: str) -> bool:
        """Check if content contains sensitive data"""
        sensitive_patterns = [
            r'"email"\s*:\s*"[^"]+@[^"]+"',
            r'"phone"\s*:\s*"[^"]+"',
            r'"address"\s*:\s*"[^"]+"',
            r'"ssn"\s*:\s*"[^"]+"',
            r'"credit_card"\s*:\s*"[^"]+"',
            r'<input[^>]*type=["\']password["\'][^>]*>',
            r'<input[^>]*value=["\'][^"\']*["\'][^>]*name=["\'](password|passwd|pwd)["\']',
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def contains_user_data(self, content: str) -> bool:
        """Check if content contains user-specific data"""
        user_patterns = [
            r'"username"\s*:\s*"[^"]+"',
            r'"name"\s*:\s*"[^"]+"',
            r'"first_name"\s*:\s*"[^"]+"',
            r'"last_name"\s*:\s*"[^"]+"',
            r'"user_id"\s*:\s*"[^"]+"',
            r'Welcome,\s+[A-Za-z\s]+!',
            r'Hello,\s+[A-Za-z\s]+',
            r'<div[^>]*class=["\'][^"\']*user[^"\']*["\'][^>]*>',
        ]
        
        for pattern in user_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    async def run(self, target_url: str) -> Dict:
        """
        Main execution method
        Returns: {
            "vulnerable": bool,
            "findings": List[Dict],
            "stats": Dict
        }
        """
        self.logger.info(f"Starting IDOR check for: {target_url}")
        
        start_time = time.time()
        
        # Step 1: Extract potential IDs
        ids = self.extract_ids_from_url(target_url)
        
        if not ids:
            self.logger.warning("No ID patterns found in URL")
            return {
                "vulnerable": False,
                "findings": [],
                "stats": {
                    "ids_found": 0,
                    "tests_performed": 0,
                    "execution_time": time.time() - start_time
                }
            }
        
        self.logger.info(f"Found {len(ids)} potential ID(s)")
        
        # Step 2: Test each ID
        all_vulns = []
        for param_name, original_value, id_type in ids:
            self.logger.debug(f"Testing parameter: {param_name} = {original_value} ({id_type})")
            
            # Generate test values
            test_values = self.generate_test_values(original_value, id_type)
            
            if not test_values:
                continue
            
            # Test parameter
            vulns = await self.test_parameter(
                target_url, param_name, original_value, id_type, test_values
            )
            
            all_vulns.extend(vulns)
        
        # Step 3: Also test for horizontal escalation
        if self.config.get('test_horizontal_escalation', True):
            horizontal_vulns = await self.test_horizontal_escalation(target_url)
            all_vulns.extend(horizontal_vulns)
        
        execution_time = time.time() - start_time
        
        # Step 4: Compile results
        result = {
            "vulnerable": len(all_vulns) > 0,
            "findings": all_vulns,
            "stats": {
                "ids_found": len(ids),
                "tests_performed": len(ids) * 8,
                "vulnerabilities_found": len(all_vulns),
                "execution_time": execution_time
            }
        }
        
        self.metrics['test_cases_run'] = result['stats']['tests_performed']
        
        return result
    
    async def test_horizontal_escalation(self, target_url: str) -> List[Dict]:
        """Test for horizontal privilege escalation"""
        vulnerabilities = []
        
        # Test common user ID patterns in different contexts
        test_patterns = [
            ('user_id', ['1', '2', '100', 'admin', 'administrator']),
            ('uid', ['1', '2', '0', 'root']),
            ('id', ['1', '2', '999']),
        ]
        
        for param_name, test_values in test_patterns:
            for test_value in test_values:
                try:
                    # Build test URL
                    parsed = urlparse(target_url)
                    query_dict = parse_qs(parsed.query, keep_blank_values=True)
                    query_dict[param_name] = [test_value]
                    
                    new_query = urlencode(query_dict, doseq=True)
                    test_url = parsed._replace(query=new_query).geturl()
                    
                    # Make request
                    response = await self.safe_request(
                        method="GET",
                        url=test_url
                    )
                    
                    if not response or not response.ok:
                        continue
                    
                    # Check for user-specific content
                    if self.contains_user_data(response.text):
                        vuln = {
                            "type": "Horizontal Privilege Escalation",
                            "url": test_url,
                            "parameter": param_name,
                            "test_value": test_value,
                            "status_code": response.status,
                            "confidence": "MEDIUM",
                            "description": "Possible horizontal privilege escalation via parameter manipulation",
                            "recommendation": "Implement proper session-based access control",
                            "evidence": {
                                "tested_parameter": param_name,
                                "test_value": test_value,
                                "user_data_found": True
                            }
                        }
                        
                        vulnerabilities.append(vuln)
                        self.add_finding(vuln)
                        
                except Exception as e:
                    self.logger.error(f"Horizontal escalation test failed: {e}")
                    continue
        
        return vulnerabilities