"""
SQL Injection Detector
Enhanced with:
1. WAF Evasion (Smart Payloads)
2. Fail-Fast Logic (Stop on first find per param)
3. Robust Error Handling
"""

import re
import os
import time
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode

# استيراد الكلاس الأب
from .base_check import BaseVulnCheck
# استيراد مولد البايلودز الذكي (للمراوغة)
from .base import PayloadGenerator 

class SQLIChecker(BaseVulnCheck):
    """SQL Injection detector with time-based, error-based, and boolean-based detection"""
    
    def __init__(self, http_client, config):
        super().__init__(http_client, config)
        
        # 1. محاولة تحميل البايلودز من الملف الخارجي (sqli.txt)
        self.payloads = self.load_payloads('sqli')
        
        # 2. إذا لم يوجد ملف، استخدم المولد الذكي مع تفعيل التخفي (Tampering)
        if not self.payloads:
            # Check if tamper is enabled in config (passed from main.py)
            use_tamper = getattr(self.config, 'tamper', True) 
            self.payloads = PayloadGenerator.generate_sqli_payloads(tamper=use_tamper)
            self.logger.info(f"Using generated payloads (Tamper={use_tamper})")
        
        # أنماط أخطاء قواعد البيانات المشهورة
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"SQLServer JDBC Driver",
            r"Oracle.*Driver",
            r"Oracle.*DB2",
            r"Microsoft Access Driver",
            r"JET Database Engine",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Unclosed quotation mark",
            r"syntax error",
        ]
    
    @property
    def name(self) -> str:
        return "SQL Injection Checker"
    
    @property
    def severity(self) -> str:
        return "CRITICAL"
        
    async def test_boolean_based(self, url: str, param: str, original_val: str) -> Optional[Dict]:
        """
        Test for Boolean-based Blind SQLi.
        Compares response length between TRUE statement (1=1) and FALSE statement (1=2).
        """
        # تجهيز بايلود الصح والخطأ
        true_payload = f"{original_val}' AND 1=1--"
        false_payload = f"{original_val}' AND 1=2--"
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # دالة مساعدة لبناء الرابط
        def make_url(p_val):
            params[param] = [p_val]
            query = urlencode(params, doseq=True)
            return parsed._replace(query=query).geturl()
            
        try:
            # استخدام safe_request بدلاً من request المباشر
            resp_true = await self.safe_request("GET", make_url(true_payload))
            resp_false = await self.safe_request("GET", make_url(false_payload))
            
            if resp_true and resp_false and hasattr(resp_true, 'text') and hasattr(resp_false, 'text'):
                # مقارنة طول الاستجابة
                if abs(len(resp_true.text) - len(resp_false.text)) > 50:
                    # التأكد من أن الحالتين رجعوا 200 OK لضمان دقة الفحص
                    if resp_true.status == resp_false.status == 200:
                        return {
                            "type": "Boolean-based Blind SQLi",
                            "url": url,
                            "parameter": param,
                            "true_response_length": len(resp_true.text),
                            "false_response_length": len(resp_false.text),
                            "confidence": "MEDIUM",
                            "description": "Different response length detected between TRUE and FALSE conditions",
                            "recommendation": "Use parameterized queries/Prepared Statements"
                        }
        except Exception as e:
            self.logger.debug(f"Boolean check failed: {e}")
            pass
        return None

    async def run(self, target_url: str) -> Dict:
        """Execute SQL injection scan with Fail-Fast logic"""
        self.logger.info(f"Starting SQL injection scan for: {target_url}")
        start_time = time.time()
        
        findings = []
        parsed = urlparse(target_url)
        query_params = parse_qs(parsed.query)
        
        if not query_params:
            self.logger.info("No parameters to test for SQLi")
            return {"vulnerable": False, "findings": []}
            
        self.logger.info(f"Found {len(query_params)} parameter(s) to test")
        
        # التكرار على كل باراميتر في الرابط
        for param, values in query_params.items():
            param_vulnerable = False  # علامة للتوقف الذكي (Smart Stop Flag)
            
            # --- المرحلة 1: فحص الأخطاء والوقت (Error & Time Based) ---
            for payload in self.payloads:
                # 🛑 التوقف الذكي: لو لقينا ثغرة في الباراميتر ده، مفيش داعي نجرب باقي البايلودز
                if param_vulnerable: 
                    break 
                
                # تجهيز الرابط
                test_params = query_params.copy()
                test_params[param] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = parsed._replace(query=test_query).geturl()
                
                req_start = time.time()
                # إرسال الطلب
                response = await self.safe_request("GET", test_url)
                req_duration = time.time() - req_start
                
                if not response: continue
                
                response_text = response.text if hasattr(response, 'text') else ""
                
                # أ) فحص الأخطاء (Error-Based)
                for pattern in self.error_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        finding = {
                            "type": "Error-based SQLi",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "status_code": response.status,
                            "confidence": "HIGH",
                            "description": f"SQL error found in response for parameter {param}",
                            "recommendation": "Use parameterized queries, prepared statements",
                            "evidence": f"SQL error pattern matched: {pattern}"
                        }
                        findings.append(finding)
                        self.add_finding(finding)
                        param_vulnerable = True # ✅ علمنا الباراميتر كمصاب
                        break # اخرج من لوب الأنماط
                
                if param_vulnerable: break # اخرج من لوب البايلودز
                
                # ب) فحص الوقت (Time-Based)
                if "SLEEP" in payload.upper() or "WAIT" in payload.upper():
                    # لو التأخير زاد عن 5 ثواني
                    if req_duration > 5:
                        finding = {
                            "type": "Time-based Blind SQLi",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "response_time": f"{req_duration:.2f}s",
                            "severity": self.severity,
                            "confidence": "HIGH",
                            "description": f"Response delayed by {req_duration:.2f}s with sleep payload",
                            "recommendation": 'Implement WAF rules and query timeout limits',
                            "evidence": 'Time delay detected'
                        }
                        findings.append(finding)
                        self.add_finding(finding)
                        param_vulnerable = True # ✅ علمنا الباراميتر كمصاب
                        break # اخرج من لوب البايلودز
                
            # --- المرحلة 2: فحص البوليان (Boolean Based) ---
            # يتم تنفيذه فقط لو الباراميتر لسه سليم (لأن الفحوصات اللي فاتت أسرع وأوضح)
            if not param_vulnerable:
                value = values[0] if values else ""
                bool_result = await self.test_boolean_based(target_url, param, value)
                if bool_result:
                    findings.append(bool_result)
                    self.add_finding(bool_result)
                    # مش محتاجين break هنا لأنه آخر فحص للباراميتر ده
        
        execution_time = time.time() - start_time
        
        return {
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "stats": {
                "parameters_tested": len(query_params),
                "payloads_tested": len(self.payloads) * len(query_params), # تقريبي
                "vulnerabilities_found": len(findings),
                "execution_time": execution_time
            }
        }