"""Advanced XSS (Cross-Site Scripting) Detector - Enhanced with Wordlist"""

import re
import os
import json
import html
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote

from .base_check import BaseVulnCheck
from utils.helpers import helpers
from utils.logger import logger

class XSSChecker(BaseVulnCheck):
    """Advanced XSS detector with multiple payload types and contexts"""
    
    def __init__(self, http_client, config):
        super().__init__(http_client, config)
        
        # Load XSS payloads from wordlist
        self.payloads = self.load_payloads('xss')
        
        # If wordlist is empty, use default payloads
        if not self.payloads:
            self.payloads = [
                '<script>alert(document.domain)</script>',
                '<img src=x onerror=alert(document.domain)>',
                '<svg onload=alert(document.domain)>',
                '" onmouseover="alert(document.domain)',
                "' onfocus='alert(document.domain)'",
                'javascript:alert(document.domain)',
            ]
        
        # Context detection patterns
        self.context_patterns = {
            'html': r'<[^>]*>',
            'attribute': r'[a-z-]+=["\'][^"\']*["\']',
            'javascript': r'<script[^>]*>|javascript:|on\w+\s*=',
            'url': r'https?://[^\s<>"\']+|/[^\s<>"\']*',
        }
    
    @property
    def name(self) -> str:
        return "XSS Checker"
    
    @property
    def severity(self) -> str:
        return "HIGH"
    
    @property
    def description(self) -> str:
        return "Cross-Site Scripting - Checks for client-side script injection vulnerabilities"
    
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
    
    def extract_parameters(self, url: str) -> Dict[str, List[str]]:
        """Extract all parameters from URL with context detection"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Also check fragment for single page apps
        if parsed.fragment and '?' in parsed.fragment:
            fragment_params = parse_qs(parsed.fragment.split('?')[1], keep_blank_values=True)
            query_params.update(fragment_params)
        
        return query_params
    
    def detect_context(self, original_value: str, response_text: str) -> List[str]:
        """Detect the context where the parameter appears"""
        contexts = []
        
        # HTML encode for searching in response
        encoded_value = html.escape(original_value)
        
        # Find all occurrences in response
        positions = []
        for match in re.finditer(re.escape(original_value), response_text):
            positions.append(match.start())
        
        for match in re.finditer(re.escape(encoded_value), response_text):
            positions.append(match.start())
        
        # Analyze context around each position
        for pos in positions[:5]:  # Limit to first 5 occurrences
            # Get surrounding text
            start = max(0, pos - 100)
            end = min(len(response_text), pos + 100)
            context = response_text[start:end]
            
            # Check for HTML tags
            if re.search(r'<[^>]*>' + re.escape(original_value) + r'[^<]*>', context):
                contexts.append('html')
            
            # Check for attribute context
            if re.search(r'[a-z-]+=["\'][^"\']*' + re.escape(original_value) + r'[^"\']*["\']', context, re.IGNORECASE):
                contexts.append('attribute')
            
            # Check for JavaScript context
            if re.search(r'<script[^>]*>[^<]*' + re.escape(original_value), context, re.IGNORECASE):
                contexts.append('javascript')
            
            # Check for URL context
            if re.search(r'href=["\']?[^"\']*' + re.escape(original_value), context, re.IGNORECASE):
                contexts.append('url')
        
        return list(set(contexts))  # Remove duplicates
    
    async def test_reflected_xss(self, url: str, param: str, value: str, 
                                payload: str, context: str = None) -> Optional[Dict]:
        """Test for reflected XSS with specific payload"""
        # Build test URL
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        
        if param in query_dict:
            query_dict[param] = [payload]
        
        new_query = urlencode(query_dict, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        
        # Make request
        response = await self.safe_request("GET", test_url)
        
        if not response or not response.ok:
            return None
        
        # Check if payload is reflected
        reflection_analysis = self.analyze_reflection(payload, response.text)
        
        if reflection_analysis['reflected']:
            # Check if payload executes (simple heuristic)
            executes = self.check_payload_execution(payload, response.text, context)
            
            return {
                'type': 'Reflected XSS',
                'url': test_url,
                'parameter': param,
                'payload': payload,
                'context': context or 'unknown',
                'status_code': response.status,
                'reflected': True,
                'execution_possible': executes,
                'confidence': self.calculate_xss_confidence(reflection_analysis, executes),
                'description': f'Reflected XSS vulnerability in {param} parameter',
                'recommendation': 'Implement proper output encoding and Content Security Policy',
                'evidence': {
                    'payload': payload,
                    'reflection_analysis': reflection_analysis,
                    'context': context
                }
            }
        
        return None
    
    def analyze_reflection(self, payload: str, response_text: str) -> Dict:
        """Analyze how the payload is reflected"""
        analysis = {
            'reflected': False,
            'positions': [],
            'encoding_detected': [],
            'exact_match': False,
            'partial_match': False
        }
        
        # Check for exact reflection
        if payload in response_text:
            analysis['reflected'] = True
            analysis['exact_match'] = True
            analysis['positions'].append('exact')
        
        # Check for HTML encoded reflection
        html_encoded = html.escape(payload)
        if html_encoded in response_text:
            analysis['reflected'] = True
            analysis['encoding_detected'].append('html')
            analysis['positions'].append('html_encoded')
        
        # Check for URL encoded reflection
        url_encoded = quote(payload)
        if url_encoded in response_text:
            analysis['reflected'] = True
            analysis['encoding_detected'].append('url')
            analysis['positions'].append('url_encoded')
        
        # Check for partial reflection (split across HTML)
        if not analysis['reflected']:
            # Split payload and check for parts
            parts = re.split(r'[<>"\']', payload)
            parts = [p for p in parts if len(p) > 3]
            
            if len(parts) > 1:
                all_parts_found = all(part in response_text for part in parts)
                if all_parts_found:
                    analysis['reflected'] = True
                    analysis['partial_match'] = True
                    analysis['positions'].append('split')
        
        return analysis
    
    def check_payload_execution(self, payload: str, response_text: str, context: str = None) -> bool:
        """Check if payload might execute (heuristic)"""
        # Check for script tags
        if '<script>' in payload.lower() and '<script>' in response_text.lower():
            # Check if script tag is not commented out or encoded
            script_pos = response_text.lower().find('<script>')
            if script_pos != -1:
                # Check surrounding characters
                before = response_text[max(0, script_pos-10):script_pos]
                after = response_text[script_pos:min(len(response_text), script_pos+50)]
                
                # Should not be in comment or attribute
                if '<!--' not in before and '="' not in before[-5:]:
                    return True
        
        # Check for event handlers
        event_handlers = ['onload=', 'onerror=', 'onclick=', 'onmouseover=']
        for handler in event_handlers:
            if handler in payload.lower() and handler in response_text.lower():
                # Check if it's in attribute context
                handler_pos = response_text.lower().find(handler)
                if handler_pos != -1:
                    # Look for opening quote before handler
                    substr = response_text[max(0, handler_pos-20):handler_pos]
                    if '"' in substr or "'" in substr:
                        return True
        
        # Check for javascript: URLs
        if 'javascript:' in payload.lower() and 'javascript:' in response_text.lower():
            # Check if it's in href or similar attribute
            js_pos = response_text.lower().find('javascript:')
            if js_pos != -1:
                # Look for href= or similar before
                substr = response_text[max(0, js_pos-50):js_pos]
                if any(attr in substr for attr in ['href=', 'src=', 'action=']):
                    return True
        
        return False
    
    def calculate_xss_confidence(self, reflection_analysis: Dict, executes: bool) -> str:
        """Calculate confidence level for XSS detection"""
        if executes:
            return 'HIGH'
        
        if reflection_analysis['exact_match']:
            return 'MEDIUM'
        
        if reflection_analysis['partial_match'] or reflection_analysis['encoding_detected']:
            return 'LOW'
        
        return 'NONE'
    
    async def run(self, target_url: str) -> Dict:
        """Execute XSS scan with wordlist"""
        self.logger.info(f"Starting XSS scan for: {target_url}")
        start_time = time.time()
        
        # Get URL parameters
        parameters = self.extract_parameters(target_url)
        
        if not parameters:
            self.logger.warning("No parameters found for XSS testing")
            return {
                "vulnerable": False,
                "findings": [],
                "stats": {
                    "parameters_tested": 0,
                    "payloads_tested": 0,
                    "execution_time": time.time() - start_time
                }
            }
        
        self.logger.info(f"Found {len(parameters)} parameter(s) to test")
        
        # Get baseline response for context analysis
        baseline_response = await self.safe_request("GET", target_url)
        baseline_text = baseline_response.text if baseline_response else ""
        
        all_findings = []
        total_payloads_tested = 0
        
        # Test each parameter with each payload type
        for param, values in parameters.items():
            for value in values[:2]:  # Test first 2 values per parameter
                # Detect context for this parameter
                contexts = self.detect_context(value, baseline_text) if baseline_text else ['unknown']
                
                if not contexts:
                    contexts = ['unknown']
                
                # Test with payloads for each detected context
                for context in contexts:
                    payloads_to_test = self.payloads[:10]  # Test first 10 payloads
                    
                    for payload in payloads_to_test:
                        total_payloads_tested += 1
                        
                        self.logger.debug(f"Testing {param} with payload")
                        
                        result = await self.test_reflected_xss(
                            target_url, param, value, payload, context
                        )
                        
                        if result:
                            all_findings.append(result)
                            self.add_finding({
                                "type": "XSS",
                                "url": result['url'],
                                "parameter": result['parameter'],
                                "payload": result['payload'],
                                "severity": self.severity,
                                "confidence": result['confidence'],
                                "description": result['description'],
                                "recommendation": result['recommendation'],
                                "evidence": str(result['evidence'])
                            })
                            
                            # Early exit if high confidence
                            if result['confidence'] == 'HIGH':
                                break
        
        execution_time = time.time() - start_time
        
        self.metrics['test_cases_run'] = total_payloads_tested
        
        return {
            "vulnerable": len(all_findings) > 0,
            "findings": all_findings,
            "stats": {
                "parameters_tested": len(parameters),
                "payloads_tested": total_payloads_tested,
                "vulnerabilities_found": len(all_findings),
                "execution_time": execution_time
            }
        }