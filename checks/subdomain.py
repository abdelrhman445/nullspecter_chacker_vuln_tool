"""
Subdomain Scanner - Enumerates subdomains using public CT logs (crt.sh)
Location: checks/subdomain.py
"""
import asyncio
import json
from typing import Dict, List, Set
from urllib.parse import urlparse
from .base_check import BaseVulnCheck

class SubdomainChecker(BaseVulnCheck):
    
    def __init__(self, http_client, config):
        super().__init__(http_client, config)
        self.crt_sh_url = "https://crt.sh/?q=%.{domain}&output=json"

    @property
    def name(self) -> str:
        return "Subdomain Scanner"

    @property
    def severity(self) -> str:
        return "INFO"

    async def run(self, target_url: str) -> Dict:
        """تشغيل فحص النطاقات الفرعية"""
        domain = urlparse(target_url).netloc.replace("www.", "")
        if not domain:
            return {}
            
        self.logger.info(f"Enumerating subdomains for: {domain}")
        
        findings = []
        subdomains = set()
        
        try:
            # استخدام safe_request للاتصال بـ crt.sh
            url = self.crt_sh_url.format(domain=domain)
            response = await self.safe_request("GET", url, timeout=20)
            
            if response and response.status == 200:
                try:
                    data = json.loads(response.text)
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for sub in name_value.split('\n'):
                            if domain in sub and '*' not in sub:
                                subdomains.add(sub.strip())
                except json.JSONDecodeError:
                    self.logger.debug("Failed to parse crt.sh JSON")
                    
        except Exception as e:
            self.logger.debug(f"Subdomain scan error: {e}")

        if subdomains:
            self.logger.info(f"Found {len(subdomains)} subdomains")
            # تجميع النتائج في Finding واحد كبير أو عدة Findings
            finding = {
                "type": "Subdomain Enumeration",
                "url": target_url,
                "count": len(subdomains),
                "severity": "INFO",
                "confidence": "HIGH",
                "description": f"Discovered {len(subdomains)} subdomains via Certificate Transparency logs",
                "recommendation": "Review these subdomains for forgotten dev/staging environments.",
                "evidence": ", ".join(list(subdomains)[:10]) + "..." # عرض أول 10 فقط
            }
            findings.append(finding)
            self.add_finding(finding)
            
            # (اختياري) حفظ النطاقات في ملف نصي
            try:
                with open(f"subdomains_{domain}.txt", "w") as f:
                    f.write("\n".join(subdomains))
            except:
                pass

        return {"vulnerable": False, "findings": findings} # INFO severity isn't a "vulnerability" usually