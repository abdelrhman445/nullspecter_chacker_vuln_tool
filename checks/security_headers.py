"""
Security Headers Checker
Enhanced to load dangerous headers from external wordlist
"""

from typing import Dict, List
from pathlib import Path
from .base_check import BaseVulnCheck


class SecurityHeadersChecker(BaseVulnCheck):
    """Security headers analyzer and checker"""
    
    def __init__(self, http_client, config):
        super().__init__(http_client, config)
        
        # Required security headers configuration
        self.required_headers = {
            'Strict-Transport-Security': {
                'required': True,
                'recommended': 'max-age=31536000; includeSubDomains; preload',
                'severity': 'HIGH',
                'description': 'Ensures all communication is over HTTPS'
            },
            'Content-Security-Policy': {
                'required': True,
                'recommended': "default-src 'self'",
                'severity': 'HIGH',
                'description': 'Prevents XSS and data injection attacks'
            },
            'X-Frame-Options': {
                'required': True,
                'recommended': 'DENY or SAMEORIGIN',
                'severity': 'MEDIUM',
                'description': 'Prevents clickjacking attacks'
            },
            'X-Content-Type-Options': {
                'required': True,
                'recommended': 'nosniff',
                'severity': 'MEDIUM',
                'description': 'Prevents MIME type sniffing'
            },
            'Referrer-Policy': {
                'required': False,
                'recommended': 'strict-origin-when-cross-origin',
                'severity': 'LOW',
                'description': 'Controls referrer information'
            },
            'Permissions-Policy': {
                'required': False,
                'recommended': 'geolocation=(), microphone=(), camera=()',
                'severity': 'LOW',
                'description': 'Controls browser features'
            },
            'X-XSS-Protection': {
                'required': False,
                'recommended': '1; mode=block',
                'severity': 'LOW',
                'description': 'Legacy XSS protection (deprecated)'
            }
        }
        
        # Default Headers that should NOT be present (Fallback)
        self.default_dangerous_headers = [
            'Server',
            'X-Powered-By',
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            'X-Runtime',
            'X-Version'
        ]
        
        # Load dangerous headers from wordlist
        self.dangerous_headers = self._load_wordlist()
    
    @property
    def name(self) -> str:
        return "Security Headers Checker"
    
    @property
    def severity(self) -> str:
        return "LOW"
    
    def _load_wordlist(self) -> List[str]:
        """Load Dangerous Headers from wordlist file"""
        # Determine paths:
        # 1. Relative to current working directory (where main.py is run)
        # 2. Relative to this script file (in case run from elsewhere)
        possible_paths = [
            Path("data/wordlists/headers.txt"),
            Path(__file__).resolve().parent.parent / "data/wordlists/headers.txt"
        ]
        
        headers = []
        for path in possible_paths:
            if path.exists():
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        headers = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    self.logger.info(f"Loaded {len(headers)} dangerous headers from wordlist: {path.name}")
                    return headers
                except Exception as e:
                    self.logger.warning(f"Error loading headers wordlist from {path}: {e}")
        
        # Fallback to default
        self.logger.info("Using built-in default dangerous headers (Wordlist not found)")
        return self.default_dangerous_headers
    
    def analyze_headers(self, headers: Dict) -> List[Dict]:
        """Analyze security headers and return findings"""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check required headers
        for header_name, header_info in self.required_headers.items():
            header_lower = header_name.lower()
            
            if header_info['required'] and header_lower not in headers_lower:
                findings.append({
                    'type': 'Missing Security Header',
                    'header': header_name,
                    'severity': header_info['severity'],
                    'description': header_info['description'],
                    'recommendation': f"Add header: {header_name}: {header_info['recommended']}",
                    'status': 'MISSING'
                })
            elif header_lower in headers_lower:
                actual_value = headers_lower[header_lower]
                recommended = header_info['recommended'].lower()
                
                # Loose check to avoid false positives on partial matches
                if recommended not in actual_value.lower() and len(recommended) > 1:
                    findings.append({
                        'type': 'Non-Optimal Header Value',
                        'header': header_name,
                        'severity': 'LOW',
                        'description': f"Header value could be improved",
                        'current_value': actual_value,
                        'recommended_value': header_info['recommended'],
                        'status': 'SUBOPTIMAL'
                    })
                else:
                    findings.append({
                        'type': 'Good Security Header',
                        'header': header_name,
                        'severity': 'INFO',
                        'description': f"Header properly configured",
                        'status': 'GOOD'
                    })
        
        # Check for dangerous headers
        for dangerous_header in self.dangerous_headers:
            header_lower = dangerous_header.lower()
            if header_lower in headers_lower:
                findings.append({
                    'type': 'Information Disclosure Header',
                    'header': dangerous_header,
                    'severity': 'LOW',
                    'description': 'Header exposes server/technology information',
                    'value': headers_lower[header_lower],
                    'recommendation': f"Remove or obscure the {dangerous_header} header",
                    'status': 'DANGEROUS'
                })
        
        # Check cookie security flags
        if 'set-cookie' in headers_lower:
            cookies = headers_lower['set-cookie']
            if isinstance(cookies, str):
                cookies = [cookies]
            
            for i, cookie in enumerate(cookies):
                cookie_lower = str(cookie).lower()
                missing_flags = []
                
                if 'httponly' not in cookie_lower:
                    missing_flags.append('HttpOnly')
                if 'secure' not in cookie_lower:
                    missing_flags.append('Secure')
                if 'samesite' not in cookie_lower:
                    missing_flags.append('SameSite')
                elif 'samesite=none' in cookie_lower and 'secure' not in cookie_lower:
                    missing_flags.append('SameSite=None without Secure')
                
                if missing_flags:
                    findings.append({
                        'type': 'Insecure Cookie',
                        'header': 'Set-Cookie',
                        'severity': 'MEDIUM',
                        'description': f'Cookie missing security flags: {", ".join(missing_flags)}',
                        'cookie_index': i,
                        'missing_flags': missing_flags,
                        'recommendation': 'Add missing security flags to cookie',
                        'status': 'INSECURE'
                    })
        
        return findings
    
    def calculate_security_score(self, findings: List[Dict]) -> Dict:
        """Calculate security score based on findings"""
        total_points = 0
        earned_points = 0
        
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 5,
            'LOW': 3,
            'INFO': 0
        }
        
        # Basic scoring logic
        for finding in findings:
            severity = finding.get('severity', 'LOW').upper()
            status = finding.get('status', '')
            
            if severity in severity_weights:
                total_points += severity_weights[severity]
                if status == 'GOOD':
                    earned_points += severity_weights[severity]
                elif status == 'SUBOPTIMAL':
                    earned_points += severity_weights[severity] // 2
        
        # Penalty logic for vulnerabilities
        score = 100
        dangerous_count = len([f for f in findings if f.get('status') == 'DANGEROUS'])
        insecure_cookies = len([f for f in findings if f.get('status') == 'INSECURE'])
        missing_high = len([f for f in findings if f.get('status') == 'MISSING' and f.get('severity') == 'HIGH'])
        missing_med = len([f for f in findings if f.get('status') == 'MISSING' and f.get('severity') == 'MEDIUM'])
        
        score -= (missing_high * 15)
        score -= (missing_med * 10)
        score -= (dangerous_count * 5)
        score -= (insecure_cookies * 10)
        
        score = max(0, min(100, score))
        
        if score >= 90: grade = 'A'
        elif score >= 80: grade = 'B'
        elif score >= 70: grade = 'C'
        elif score >= 60: grade = 'D'
        else: grade = 'F'
        
        return {
            'score': round(score, 1),
            'grade': grade,
            'percentage': f"{round(score)}%"
        }
    
    async def run(self, target_url: str) -> Dict:
        """Execute security headers scan"""
        self.logger.info(f"Starting Security Headers scan for: {target_url}")
        
        try:
            response = await self.http_client.request("GET", target_url)
            headers = dict(response.headers)
            
            findings = self.analyze_headers(headers)
            score = self.calculate_security_score(findings)
            
            problematic_findings = [
                f for f in findings 
                if f.get('status') in ['MISSING', 'SUBOPTIMAL', 'DANGEROUS', 'INSECURE']
            ]
            
            for finding in problematic_findings:
                self.log_finding(finding)
            
            return {
                "vulnerable": len(problematic_findings) > 0,
                "findings": problematic_findings,
                "all_findings": findings,
                "security_score": score,
                "stats": {
                    "headers_analyzed": len(headers),
                    "required_headers": len(self.required_headers),
                    "missing_headers": len([f for f in findings if f.get('status') == 'MISSING']),
                    "score": score['percentage']
                }
            }
            
        except Exception as e:
            self.logger.error(f"Security headers scan failed: {e}")
            return {
                "vulnerable": False,
                "findings": [],
                "error": str(e)
            }
    
    def log_finding(self, finding: Dict):
        """Log security header finding"""
        status = finding.get('status', '')
        header = finding.get('header', 'Unknown')
        severity = finding.get('severity', 'LOW')
        
        if status == 'MISSING':
            self.logger.warning(f"⚠️ Missing security header: {header} [{severity}]")
        elif status == 'DANGEROUS':
            self.logger.warning(f"⚠️ Dangerous header found: {header} [{severity}]")
        elif status == 'INSECURE':
            self.logger.warning(f"⚠️ Insecure cookie configuration: {header} [{severity}]")