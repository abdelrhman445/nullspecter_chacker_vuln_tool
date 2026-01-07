"""
Shodan Recon Module - Passive intelligence gathering via Shodan API
Location: checks/shodan_check.py
"""
import socket
from typing import Dict, List
from urllib.parse import urlparse
from .base_check import BaseVulnCheck

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

class ShodanReconChecker(BaseVulnCheck):
    
    def __init__(self, http_client, config):
        super().__init__(http_client, config)
        # --- FIX: config is passed as a dict, so we must use .get() ---
        self.api_key = config.get('shodan_api_key')
        self.api = None
        
        if SHODAN_AVAILABLE and self.api_key:
            try:
                self.api = shodan.Shodan(self.api_key)
            except:
                self.api = None

    @property
    def name(self) -> str:
        return "Shodan Recon"

    @property
    def severity(self) -> str:
        return "INFO"

    async def run(self, target_url: str) -> Dict:
        """Execute Shodan check"""
        if not self.api:
            # Silent return is okay here if not configured, but helpful to debug
            if not self.api_key:
                self.logger.debug("Shodan skipped: No API Key")
            return {} 
            
        # 1. Resolve IP
        try:
            domain = urlparse(target_url).netloc
            if not domain: domain = target_url
            if ':' in domain: domain = domain.split(':')[0]
            
            target_ip = socket.gethostbyname(domain)
        except Exception as e:
            self.logger.debug(f"Could not resolve IP for Shodan: {e}")
            return {}

        self.logger.info(f"Querying Shodan for IP: {target_ip}")
        findings = []
        
        try:
            # 2. Query Shodan
            host_info = self.api.host(target_ip)
            
            # 3. Analyze Open Ports
            ports = host_info.get('ports', [])
            if ports:
                findings.append({
                    "type": "Open Ports (Shodan)",
                    "url": target_url,
                    "severity": "INFO",
                    "confidence": "HIGH",
                    "description": f"Found {len(ports)} open ports via passive recon.",
                    "evidence": f"Ports: {', '.join(map(str, ports))}",
                    "recommendation": "Ensure firewall rules block unnecessary ports."
                })
                self.add_finding(findings[-1])

            # 4. Analyze Vulnerabilities (CVEs)
            vulns = host_info.get('vulns', [])
            if vulns:
                for cve in vulns:
                    findings.append({
                        "type": "Known Vulnerability (CVE)",
                        "url": target_url,
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "description": f"Target is potentially vulnerable to {cve}",
                        "evidence": f"Detected by Shodan Analysis",
                        "recommendation": f"Patch the service associated with {cve} immediately."
                    })
                    self.add_finding(findings[-1])

            # 5. Server Info
            os_info = host_info.get('os', 'Unknown')
            org_info = host_info.get('org', 'Unknown')
            findings.append({
                "type": "Server Information",
                "url": target_url,
                "severity": "INFO",
                "confidence": "HIGH",
                "description": "Infrastructure details retrieved",
                "evidence": f"OS: {os_info} | ISP/Org: {org_info}",
                "recommendation": "N/A"
            })
            self.add_finding(findings[-1])

        except shodan.APIError as e:
            # This will now show clearly in your verbose logs
            self.logger.error(f"🚨 Shodan API Error: {e}")
        except Exception as e:
            self.logger.error(f"🚨 Shodan check failed: {e}")

        return {"vulnerable": len(findings) > 0, "findings": findings}