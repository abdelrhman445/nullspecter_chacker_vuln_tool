"""
GraphQL Vulnerability Checker
Enhanced to load endpoints from external wordlist
"""

import json
import os
from typing import Dict, List
from urllib.parse import urlparse
from pathlib import Path
from .base_check import BaseVulnCheck


class GraphQLChecker(BaseVulnCheck):
    """GraphQL vulnerability detector"""
    
    def __init__(self, http_client, config):
        super().__init__(http_client, config)
        
        # Default Common GraphQL endpoints (Fallback in case file is missing)
        self.default_endpoints = [
            '/graphql',
            '/graphql/',
            '/v1/graphql',
            '/v2/graphql',
            '/api/graphql',
            '/gql',
            '/query',
        ]
        
        # Load endpoints from wordlist
        self.graphql_endpoints = self._load_wordlist()
        
        # Introspection query to detect GraphQL
        self.introspection_query = {
            "query": """
            {
              __schema {
                types {
                  name
                  fields {
                    name
                  }
                }
              }
            }
            """
        }
    
    @property
    def name(self) -> str:
        return "GraphQL Checker"
    
    @property
    def severity(self) -> str:
        return "HIGH"
    
    def _load_wordlist(self) -> List[str]:
        """Load GraphQL endpoints from wordlist file"""
        # Try to locate the file relative to the execution path or the module
        possible_paths = [
            Path("data/wordlists/graphql_queries.txt"),
            Path(__file__).parent.parent.parent / "data/wordlists/graphql_queries.txt"
        ]
        
        endpoints = []
        
        for path in possible_paths:
            if path.exists():
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        endpoints = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    self.logger.info(f"Loaded {len(endpoints)} GraphQL endpoints from wordlist")
                    return endpoints
                except Exception as e:
                    self.logger.warning(f"Error loading GraphQL wordlist: {e}")
        
        # Fallback to default if no file found or empty
        self.logger.info("Using built-in default GraphQL endpoints")
        return self.default_endpoints

    async def discover_graphql_endpoints(self, base_url: str) -> List[str]:
        """Discover GraphQL endpoints"""
        discovered = []
        parsed_url = urlparse(base_url)
        
        # Clean base path to avoid double slashes
        base_path = parsed_url.path.rstrip('/')
        
        for endpoint in self.graphql_endpoints:
            # Ensure endpoint starts with /
            if not endpoint.startswith('/'):
                endpoint = '/' + endpoint
                
            full_path = base_path + endpoint
            test_url = parsed_url._replace(path=full_path).geturl()
            
            try:
                # Try GET request
                response = await self.http_client.request("GET", test_url)
                # 400 and 405 often indicate a valid endpoint that needs a query
                if response.status in [200, 400, 405]:
                    # Verify it's actually GraphQL by sending a test query
                    verify_response = await self.http_client.request(
                        "POST", 
                        test_url,
                        json={"query": "{__typename}"}
                    )
                    if verify_response.status == 200 and 'data' in verify_response.text:
                        discovered.append(test_url)
                        continue

                # Try POST request directly
                response = await self.http_client.request(
                    "POST", 
                    test_url,
                    json={"query": "{__typename}"}
                )
                if response.status in [200, 400] and 'data' in response.text:
                    if test_url not in discovered:
                        discovered.append(test_url)
                        
            except Exception as e:
                continue
        
        return discovered
    
    async def test_introspection(self, endpoint: str) -> bool:
        """Test if introspection is enabled"""
        try:
            response = await self.http_client.request(
                "POST",
                endpoint,
                json=self.introspection_query
            )
            
            if response.status == 200:
                data = json.loads(response.text)
                if 'data' in data and '__schema' in data['data']:
                    return True
            
        except:
            pass
        
        return False
    
    async def run(self, target_url: str) -> Dict:
        """Execute GraphQL vulnerability scan"""
        self.logger.info(f"Starting GraphQL scan for: {target_url}")
        
        findings = []
        
        # Discover GraphQL endpoints
        endpoints = await self.discover_graphql_endpoints(target_url)
        
        if not endpoints:
            return {
                "vulnerable": False,
                "findings": [],
                "stats": {"endpoints_tested": len(self.graphql_endpoints)}
            }
        
        self.logger.info(f"Found {len(endpoints)} GraphQL endpoint(s): {', '.join(endpoints)}")
        
        # Test each endpoint
        for endpoint in endpoints:
            # Test introspection
            if await self.test_introspection(endpoint):
                findings.append({
                    'type': 'GraphQL Introspection Enabled',
                    'url': endpoint,
                    'severity': 'HIGH',
                    'description': 'GraphQL introspection is enabled, exposing schema information',
                    'recommendation': 'Disable introspection in production environment',
                    'evidence': 'Introspection query returned valid schema'
                })
            
            # Test for batching attacks
            try:
                batch_payload = [
                    {"query": "{__typename}"},
                    {"query": "{__typename}"},
                    {"query": "{__typename}"}
                ]
                
                response = await self.http_client.request(
                    "POST",
                    endpoint,
                    json=batch_payload
                )
                
                if response.status == 200:
                    data = json.loads(response.text)
                    if isinstance(data, list) and len(data) > 1:
                        findings.append({
                            'type': 'GraphQL Batching Enabled',
                            'url': endpoint,
                            'severity': 'MEDIUM',
                            'description': 'GraphQL supports batch queries, which can lead to DoS attacks',
                            'recommendation': 'Implement query complexity limiting and disable batching if not needed',
                            'evidence': 'Batch query returned multiple responses'
                        })
                        
            except:
                pass
        
        # Log findings
        for finding in findings:
            self.add_finding(finding)
        
        return {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "stats": {
                "endpoints_tested": len(self.graphql_endpoints),
                "endpoints_found": len(endpoints),
                "vulnerabilities_found": len(findings)
            }
        }