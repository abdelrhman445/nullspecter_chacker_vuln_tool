"""
JS Secrets Miner - Extracts API Keys and Tokens from JavaScript files
Location: checks/js_secrets.py
"""
import re
import math
import asyncio
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from .base_check import BaseVulnCheck

class JSSecretsChecker(BaseVulnCheck):
    
    def __init__(self, http_client, config):
        super().__init__(http_client, config)
        # أنماط حساسة جداً (Regex Patterns)
        self.signatures = [
            ('Google API Key', r'AIza[0-9A-Za-z\\-_]{35}'),
            ('AWS Access Key ID', r'AKIA[0-9A-Z]{16}'),
            ('Amazon MWS Auth Token', r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
            ('Slack Token', r'xox[baprs]-([0-9a-zA-Z]{10,48})'),
            ('Stripe Publishable Key', r'pk_live_[0-9a-zA-Z]{24}'),
            ('Twilio Account SID', r'AC[a-f0-9]{32}'),
            ('Mailgun API Key', r'key-[0-9a-zA-Z]{32}'),
            ('Generic API Key', r'(?i)(?:api_key|apikey|secret|token)\s*[:=]\s*[\"\']([a-zA-Z0-9_\-]{20,})[\"\']'),
            ('JWT Token', r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
        ]

    @property
    def name(self) -> str:
        return "JS Secrets Miner"

    @property
    def severity(self) -> str:
        return "HIGH"

    def calculate_entropy(self, text: str) -> float:
        """حساب العشوائية لكشف المفاتيح غير المعروفة"""
        if not text: return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    async def fetch_js_links(self, url: str, html: str) -> Set[str]:
        """استخراج روابط JS من الصفحة"""
        js_links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for script in soup.find_all('script', src=True):
                src = script.get('src')
                if src:
                    full_url = urljoin(url, src)
                    js_links.add(full_url)
        except:
            pass
        return js_links

    async def run(self, target_url: str) -> Dict:
        """تشغيل الفحص"""
        self.logger.info(f"Scanning for JS secrets in: {target_url}")
        
        # 1. جلب الصفحة الرئيسية
        response = await self.safe_request("GET", target_url)
        if not response or not response.text:
            return {}
            
        findings = []
        # إضافة الصفحة الرئيسية للفحص أيضاً (قد تحتوي على Inline JS)
        files_to_scan = {target_url: response.text}
        
        # 2. استخراج ملفات JS الخارجية
        js_links = await self.fetch_js_links(target_url, response.text)
        if js_links:
            self.logger.info(f"Found {len(js_links)} JS file(s) to analyze")
            
            for js_link in js_links:
                # فلترة الروابط الخارجية البعيدة جداً (اختياري)
                js_resp = await self.safe_request("GET", js_link)
                if js_resp and js_resp.status == 200:
                    files_to_scan[js_link] = js_resp.text

        # 3. تحليل المحتوى
        for source_url, content in files_to_scan.items():
            if not content: continue
            
            # البحث بالأنماط
            for name, regex in self.signatures:
                matches = re.finditer(regex, content)
                for match in matches:
                    secret = match.group(0)
                    # تجاهل التطابقات القصيرة جداً أو الخاطئة
                    if len(secret) < 8: continue
                    
                    finding = {
                        "type": "Exposed Secret",
                        "url": source_url,
                        "secret_type": name,
                        "secret_preview": secret[:20] + "...", # عرض جزء فقط للأمان
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "description": f"Found sensitive {name} in source code",
                        "recommendation": "Revoke the key immediately and move it to environment variables.",
                        "evidence": secret
                    }
                    # تجنب التكرار
                    if finding not in findings:
                        findings.append(finding)
                        self.add_finding(finding)

        return {"vulnerable": len(findings) > 0, "findings": findings}