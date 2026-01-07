"""Main Scanner Engine - Orchestrates all security checks"""

import asyncio
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import json
import uuid
from datetime import datetime

from .http_client import AdvancedHTTPClient
from .database import scan_db
from utils.logger import NullSpecterLogger

@dataclass
class ScanResult:
    """Scan result container"""
    scan_id: str
    target: str
    start_time: float
    end_time: float
    duration: float
    vulnerabilities: List[Dict]
    statistics: Dict
    checkers_performed: List[str]
    risk_level: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)

class ScannerEngine:
    """Main scanning engine with database integration"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.http_client = None
        self.checks = []
        self.results = []
        self.logger = NullSpecterLogger(name="ScannerEngine")
        
        # Statistics
        self.scan_stats = {
            'total_requests': 0,
            'vulnerabilities_found': 0,
            'checks_completed': 0,
            'scans_completed': 0,
            'total_duration': 0
        }
        
    async def initialize(self):
        """Initialize engine components"""
        self.logger.info("Initializing Scanner Engine...")
        
        # Initialize HTTP client
        self.http_client = AdvancedHTTPClient(self.config)
        await self.http_client.start()
        
        # Dynamically load all available checks
        await self._load_checks()
        
        # Initialize database
        self.logger.info(f"Database initialized: {scan_db.db_path}")
        
        self.logger.info(f"Loaded {len(self.checks)} security checks")
        
    async def _load_checks(self):
        """Dynamically load all security checks"""
        try:
            # Import standard checks
            from checks.idor import IDORChecker
            from checks.xss import XSSChecker
            from checks.sqli import SQLIChecker
            from checks.open_redirect import OpenRedirectChecker
            from checks.security_headers import SecurityHeadersChecker
            from checks.graphql import GraphQLChecker
            from checks.ssrf import SSRFPayloadChecker
            from checks.cors import CORSChecker
            
            # Import analysis checks
            from checks.js_secrets import JSSecretsChecker
            from checks.subdomain import SubdomainChecker
            
            # [NEW] Import Shodan
            from checks.shodan_check import ShodanReconChecker
            
            # Register checks based on config
            default_checks = self.config.get('default_checks', [
                'idor', 'xss', 'sqli', 'open_redirect', 
                'security_headers', 'graphql', 'ssrf',
                'js_secrets', 'subdomain', 'shodan'
            ])
            
            # Map config names to classes
            check_mapping = {
                'idor': IDORChecker,
                'xss': XSSChecker,
                'sqli': SQLIChecker,
                'open_redirect': OpenRedirectChecker,
                'security_headers': SecurityHeadersChecker,
                'graphql': GraphQLChecker,
                'ssrf': SSRFPayloadChecker,
                'cors': CORSChecker,
                # Bind new checks
                'js_secrets': JSSecretsChecker,
                'subdomain': SubdomainChecker,
                'shodan': ShodanReconChecker
            }
            
            for check_name in default_checks:
                if check_name in check_mapping:
                    checker_class = check_mapping[check_name]
                    # Instantiate check with client and config
                    self.checks.append(checker_class(self.http_client, self.config))
                    self.logger.debug(f"Loaded checker: {checker_class.__name__}")
            
        except ImportError as e:
            self.logger.error(f"Failed to load some checks: {e}")
            # Fallback: Load at least basic checks if critical ones fail
            try:
                from checks.idor import IDORChecker
                from checks.xss import XSSChecker
                from checks.sqli import SQLIChecker
                
                if not self.checks:
                    self.checks.append(IDORChecker(self.http_client, self.config))
                    self.checks.append(XSSChecker(self.http_client, self.config))
                    self.checks.append(SQLIChecker(self.http_client, self.config))
            except ImportError:
                pass
    
    async def scan(self, target_url: str) -> ScanResult:
        """Execute full scan on target"""
        self.logger.info(f"Starting comprehensive scan: {target_url}")
        
        # Create scan in database
        scan_id = scan_db.create_scan(target_url, self.config)
        
        start_time = time.time()
        all_vulnerabilities = []
        checker_results = []
        
        for check in self.checks:
            try:
                self.logger.info(f"Running: {check.name}...")
                checker_start = time.time()
                
                result = await check.run(target_url)
                execution_time = time.time() - checker_start
                
                # Store checker result
                checker_result = {
                    'checker': check.name,
                    'vulnerable': result.get('vulnerable', False),
                    'findings_count': len(result.get('findings', [])),
                    'execution_time': execution_time,
                    'stats': result.get('stats', {})
                }
                checker_results.append(checker_result)
                
                # Save to database
                scan_db.add_checker_result(
                    scan_id, check.name, 
                    'completed',
                    checker_result
                )
                
                # Process findings
                if result.get("vulnerable") or result.get("findings"):
                    findings = result.get('findings', [])
                    
                    # Log based on severity
                    has_high_risk = any(f.get('severity') in ['CRITICAL', 'HIGH'] for f in findings)
                    if has_high_risk:
                        self.logger.warning(f"Found {len(findings)} finding(s) with {check.name}")
                    else:
                        self.logger.info(f"Found {len(findings)} info/finding(s) with {check.name}")
                    
                    # Add checker name to each finding
                    for finding in findings:
                        finding['checker'] = check.name
                        finding['scan_id'] = scan_id
                        all_vulnerabilities.append(finding)
                        
                        # Save to database
                        scan_db.add_vulnerability(scan_id, finding)
                        
                        # Log individual vulnerability
                        severity = finding.get('severity', 'INFO')
                        log_msg = f"{finding.get('type', 'Unknown')} found at: {finding.get('url', target_url)} [{severity}]"
                        
                        if severity in ['CRITICAL', 'HIGH']:
                            self.logger.critical(log_msg)
                        elif severity == 'INFO':
                            self.logger.info(log_msg)
                        else:
                            self.logger.warning(log_msg)
                else:
                    self.logger.info(f"No vulnerabilities found with {check.name}")
                    
                self.scan_stats['checks_completed'] += 1
                
                # Respect rate limiting between checks
                await asyncio.sleep(0.5)
                
            except Exception as e:
                self.logger.error(f"Check {check.name} failed: {str(e)[:100]}...")
                scan_db.add_checker_result(
                    scan_id, check.name, 'failed',
                    {'error': str(e), 'execution_time': time.time() - checker_start}
                )
                continue
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Calculate statistics
        critical_count = len([v for v in all_vulnerabilities if v.get('severity') == 'CRITICAL'])
        high_count = len([v for v in all_vulnerabilities if v.get('severity') == 'HIGH'])
        medium_count = len([v for v in all_vulnerabilities if v.get('severity') == 'MEDIUM'])
        low_count = len([v for v in all_vulnerabilities if v.get('severity') == 'LOW'])
        
        # Calculate risk level
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 0 or len(all_vulnerabilities) > 10:
            risk_level = "HIGH"
        elif medium_count > 0 or len(all_vulnerabilities) > 5:
            risk_level = "MEDIUM"
        elif len(all_vulnerabilities) > 0:
            risk_level = "LOW"
        else:
            risk_level = "SECURE"
        
        # Update scan in database
        scan_results = {
            'vulnerable': len(all_vulnerabilities) > 0,
            'findings': all_vulnerabilities,
            'checkers_performed': [c['checker'] for c in checker_results],
            'total_vulnerabilities': len(all_vulnerabilities),
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'risk_level': risk_level,
            'scan_duration': scan_duration
        }
        
        scan_db.update_scan_status(scan_id, 'completed', scan_results)
        
        # Update engine statistics
        self.scan_stats['vulnerabilities_found'] += len(all_vulnerabilities)
        self.scan_stats['scans_completed'] += 1
        self.scan_stats['total_duration'] += scan_duration
        
        # Compile final results
        scan_result = ScanResult(
            scan_id=scan_id,
            target=target_url,
            start_time=start_time,
            end_time=end_time,
            duration=scan_duration,
            vulnerabilities=all_vulnerabilities,
            statistics={
                'total_vulnerabilities': len(all_vulnerabilities),
                'critical_count': critical_count,
                'high_count': high_count,
                'medium_count': medium_count,
                'low_count': low_count,
                'risk_level': risk_level
            },
            checkers_performed=[check.name for check in self.checks],
            risk_level=risk_level
        )
        
        # Log completion
        if len(all_vulnerabilities) > 0:
            self.logger.critical(
                f"Scan complete: Found {len(all_vulnerabilities)} vulnerability(ies) "
                f"in {scan_duration:.2f}s"
            )
        else:
            self.logger.info(f"Scan complete: No vulnerabilities found in {scan_duration:.2f}s")
        
        return scan_result
    
    async def batch_scan(self, targets: List[str]) -> List[ScanResult]:
        """Scan multiple targets with concurrency control"""
        results = []
        max_concurrent = self.config.get('max_concurrent_scans', 3)
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(target):
            async with semaphore:
                return await self.scan(target)
        
        # Run scans concurrently
        tasks = [scan_with_semaphore(target) for target in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Scan failed: {result}")
            else:
                valid_results.append(result)
        
        return valid_results
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        avg_duration = (
            self.scan_stats['total_duration'] / self.scan_stats['scans_completed']
            if self.scan_stats['scans_completed'] > 0 else 0
        )
        
        return {
            **self.scan_stats,
            'average_scan_duration': avg_duration,
            'checks_loaded': len(self.checks),
            'database_scans': len(scan_db.get_recent_scans(limit=1000))
        }
    
    async def shutdown(self):
        """Clean shutdown"""
        if self.http_client:
            await self.http_client.close()
        
        # Log final statistics
        stats = self.get_statistics()
        self.logger.info(f"Scanner engine shutdown complete")
        self.logger.info(f"Statistics: {stats}")
        
        # Optimize database
        if scan_db.optimize_database():
            self.logger.info("Database optimized")