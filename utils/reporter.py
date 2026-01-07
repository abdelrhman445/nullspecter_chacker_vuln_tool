"""
Enhanced Report Generator for NullSpecter Scanner
Hacker/Cyberpunk Theme Edition - Final Patched Version
"""

import json
import os
import sys
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import webbrowser
import base64  # Added for safe data embedding

# Try to import optional dependencies
try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    PDFKIT_AVAILABLE = False

try:
    import markdown
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False

from .logger import logger
from .helpers import helpers


class HTMLReporter:
    """Generate professional HTML reports with Dark/Hacker Ops interface"""
    
    def __init__(self, scan_results: Dict):
        self.scan_results = scan_results
        self.timestamp = datetime.now()
        self.report_data = self._prepare_report_data()
    
    def _prepare_report_data(self) -> Dict:
        """Prepare and enrich report data"""
        vulns = self.scan_results.get('vulnerabilities', [])
        
        # Calculate statistics
        severity_count = {
            'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0
        }
        
        for vuln in vulns:
            severity = vuln.get('severity', 'LOW').upper()
            if severity in severity_count:
                severity_count[severity] += 1
            else:
                severity_count['INFO'] += 1
        
        # Categorize vulnerabilities by type
        vuln_by_type = {}
        for vuln in vulns:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(vulns)
        
        # Calculate security score (0-100)
        security_score = self._calculate_security_score(severity_count, vulns)
        
        return {
            'scan_info': {
                'target_url': self.scan_results.get('target_url', 'Unknown'),
                'scan_date': self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'scan_duration': self.scan_results.get('scan_duration', 'N/A'),
                'total_checks': len(self.scan_results.get('checkers_performed', [])),
                'risk_level': self._calculate_risk_level(severity_count),
                'scan_id': self.scan_results.get('scan_id', 'N/A')
            },
            'statistics': {
                'total_vulnerabilities': len(vulns),
                'severity_distribution': severity_count,
                'vulnerabilities_by_type': vuln_by_type,
                'security_score': security_score,
                'score_grade': self._get_score_grade(security_score)
            },
            'vulnerabilities': vulns,
            'recommendations': recommendations,
            'checkers': self.scan_results.get('checkers_performed', []),
            'metadata': {
                'generator': 'NullSpecter Ops v2.0',
                'report_id': f"OP-{self.timestamp.strftime('%Y%m%d-%H%M%S')}",
                'version': '2.0',
                'generated_at': self.timestamp.isoformat()
            }
        }
    
    def _calculate_risk_level(self, severity_count: Dict) -> str:
        """Calculate overall risk level"""
        total = sum(severity_count.values())
        critical = severity_count.get('CRITICAL', 0)
        high = severity_count.get('HIGH', 0)
        medium = severity_count.get('MEDIUM', 0)
        
        if critical > 0:
            return 'CRITICAL'
        elif high > 0 or (medium > 5):
            return 'HIGH'
        elif medium > 0:
            return 'MEDIUM'
        elif severity_count.get('LOW', 0) > 0:
            return 'LOW'
        elif severity_count.get('INFO', 0) > 0:
            return 'INFO'
        else:
            return 'SECURE'
    
    def _calculate_security_score(self, severity_count: Dict, vulnerabilities: List) -> int:
        """Calculate security score (0-100)"""
        weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 5,
            'LOW': 2,
            'INFO': 0
        }
        
        max_score = 100
        penalty = 0
        
        for severity, count in severity_count.items():
            if severity in weights:
                penalty += count * weights[severity]
        
        # Additional penalty for high confidence findings
        high_confidence_count = sum(1 for v in vulnerabilities if v.get('confidence') == 'HIGH' and v.get('severity') not in ['INFO', 'LOW'])
        penalty += high_confidence_count * 2
        
        score = max(0, min(100, max_score - penalty))
        
        return score
    
    def _get_score_grade(self, score: int) -> str:
        """Get letter grade for security score"""
        if score >= 90: return 'A'
        elif score >= 80: return 'B'
        elif score >= 70: return 'C'
        elif score >= 60: return 'D'
        else: return 'F'
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate intelligent recommendations based on findings"""
        recommendations = []
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Recommendation templates
        recommendation_templates = {
            'SQL Injection': {
                'priority': 'CRITICAL',
                'title': 'SQL Injection Detected',
                'description': 'Attackers can execute arbitrary SQL commands. Immediate remediation required.',
                'remediation': [
                    'Use parameterized queries (Prepared Statements)',
                    'Sanitize all user inputs',
                    'Enforce least privilege on DB accounts'
                ],
            },
            'XSS': {
                'priority': 'HIGH',
                'title': 'Cross-Site Scripting (XSS)',
                'description': 'Malicious scripts can be injected into trusted websites.',
                'remediation': [
                    'Implement Content Security Policy (CSP)',
                    'Encode data on output',
                    'Validate input on arrival'
                ],
            },
            'IDOR': {
                'priority': 'HIGH',
                'title': 'Insecure Direct Object References',
                'description': 'Unauthorized access to resources via direct reference manipulation.',
                'remediation': [
                    'Implement access control checks per object',
                    'Use indirect references (Random Tokens/UUIDs)'
                ]
            },
            'Subdomain Enumeration': {
                'priority': 'INFO',
                'title': 'Subdomain Exposure',
                'description': 'Publicly discoverable subdomains found via CT logs.',
                'remediation': [
                    'Review subdomains for abandoned development/staging environments',
                    'Ensure all exposed subdomains are intended to be public'
                ]
            },
            'Exposed Secret': {
                'priority': 'HIGH',
                'title': 'Sensitive Data Exposure (Secrets)',
                'description': 'API Keys or tokens found in source code.',
                'remediation': [
                    'Revoke exposed keys immediately',
                    'Move secrets to environment variables (server-side)',
                    'Remove hardcoded secrets from codebase'
                ]
            },
            'Open Ports (Shodan)': {
                'priority': 'INFO',
                'title': 'Exposed Services (Shodan)',
                'description': 'Ports and services visible to the public internet.',
                'remediation': [
                    'Close unused ports via Firewall/UFW',
                    'Put sensitive services behind VPN',
                    'Update service banners to hide versions'
                ]
            },
            'Known Vulnerability (CVE)': {
                'priority': 'CRITICAL',
                'title': 'Publicly Known Vulnerability (CVE)',
                'description': 'Server version has known exploits documented in CVE databases.',
                'remediation': [
                    'Update the affected software immediately',
                    'Apply security patches from the vendor',
                    'Check exploitability using dedicated tools'
                ]
            }
        }
        
        # Add specific recommendations for found vulnerabilities
        for vuln_type in vuln_types.keys():
            # Partial match for types (e.g., "Reflected XSS" matches "XSS")
            matched = False
            for key, template in recommendation_templates.items():
                if key in vuln_type or vuln_type in key:
                    if template not in recommendations:
                        recommendations.append(template)
                    matched = True
                    break
            
            if not matched and 'Header' in vuln_type:
                 if not any(r['title'] == 'Security Headers' for r in recommendations):
                    recommendations.append({
                        'priority': 'MEDIUM',
                        'title': 'Security Headers',
                        'description': 'Missing or misconfigured security headers.',
                        'remediation': ['Configure HSTS, CSP, X-Frame-Options, and X-Content-Type-Options headers']
                    })

        # Add general security recommendations if list is not empty or as default
        if not recommendations and vulnerabilities:
             recommendations.append({
                'priority': 'MEDIUM',
                'title': 'General Hardening',
                'description': 'Improve overall security posture.',
                'remediation': [
                    'Keep software updated',
                    'Implement HTTPS (HSTS)',
                    'Review server logs regularly'
                ]
            })
        
        return recommendations
    
    def generate_report(self, output_file: str = None, open_in_browser: bool = True) -> str:
        """Generate comprehensive HTML report"""
        if not output_file:
            output_file = f"nullspecter_ops_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.html"
        
        # Ensure output directory exists
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load HTML template
        html_content = self._generate_html_content()
        
        # Save to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_file}")
        
        # Try to open in browser
        if open_in_browser:
            try:
                webbrowser.open(f'file://{output_path.absolute()}')
            except:
                logger.warning("Could not open report in browser")
        
        return output_file
    
    def _generate_html_content(self) -> str:
        """Generate HTML content for the report with Hacker/Cyberpunk Theme"""
        
        json_data = json.dumps(self.report_data, ensure_ascii=False)
        json_safe = json_data.replace('/', '\\/') 
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NullSpecter // OPS REPORT // {self.report_data['metadata']['report_id']}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Rajdhani:wght@500;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-dark: #050505;
            --bg-panel: #0d0e14;
            --bg-panel-hover: #151720;
            --neon-blue: #00f3ff;
            --neon-green: #0aff0a;
            --neon-red: #ff003c;
            --neon-yellow: #fcee0a;
            --text-main: #e0e6ed;
            --text-dim: #6c7a89;
            --border-color: #1f293a;
            --grid-color: rgba(0, 243, 255, 0.04);
            --code-bg: #000000;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'JetBrains Mono', monospace;
            background-color: var(--bg-dark);
            color: var(--text-main);
            min-height: 100vh;
            padding: 20px;
            background-image: 
                linear-gradient(var(--grid-color) 1px, transparent 1px),
                linear-gradient(90deg, var(--grid-color) 1px, transparent 1px);
            background-size: 30px 30px;
            overflow-x: hidden;
        }}

        /* Scanline Effect */
        body::before {{
            content: " ";
            display: block;
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            right: 0;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
            z-index: 9999;
            background-size: 100% 2px, 3px 100%;
            pointer-events: none;
        }}

        .container {{
            max-width: 1600px;
            margin: 0 auto;
            position: relative;
            z-index: 1;
        }}
        
        /* Header Section */
        .header {{
            border-bottom: 2px solid var(--neon-blue);
            padding-bottom: 20px;
            margin-bottom: 40px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            position: relative;
            background: linear-gradient(90deg, rgba(0,243,255,0.05) 0%, rgba(0,0,0,0) 100%);
            padding: 20px;
        }}

        .header h1 {{
            font-family: 'Rajdhani', sans-serif;
            font-size: 3em;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: white;
            text-shadow: 0 0 10px rgba(0, 243, 255, 0.5);
        }}

        .header .subtitle {{
            color: var(--neon-green);
            font-size: 0.9em;
            letter-spacing: 1px;
            margin-top: 5px;
        }}

        .header-stats {{
            text-align: right;
        }}

        .risk-badge {{
            display: inline-block;
            padding: 8px 20px;
            border: 2px solid currentColor;
            font-weight: bold;
            font-size: 1.4em;
            text-transform: uppercase;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
            background: rgba(0,0,0,0.8);
            letter-spacing: 2px;
        }}
        
        .risk-CRITICAL {{ color: var(--neon-red); box-shadow: 0 0 15px var(--neon-red); text-shadow: 0 0 5px var(--neon-red); }}
        .risk-HIGH {{ color: #ff8c00; box-shadow: 0 0 15px #ff8c00; text-shadow: 0 0 5px #ff8c00;}}
        .risk-MEDIUM {{ color: var(--neon-yellow); }}
        .risk-LOW {{ color: var(--neon-blue); }}
        .risk-INFO {{ color: var(--neon-green); }}
        .risk-SECURE {{ color: var(--neon-green); border-color: var(--neon-green); }}

        /* Dashboard Grid */
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .panel {{
            background: var(--bg-panel);
            border: 1px solid var(--border-color);
            padding: 20px;
            position: relative;
            transition: all 0.3s ease;
        }}

        .panel:hover {{
            border-color: var(--neon-blue);
            box-shadow: 0 0 15px rgba(0, 243, 255, 0.1);
            background: var(--bg-panel-hover);
            transform: translateY(-2px);
        }}

        .panel-corner {{
            position: absolute;
            width: 10px;
            height: 10px;
            border: 1px solid var(--neon-blue);
            transition: all 0.3s;
            opacity: 0.7;
        }}
        .panel-corner.tl {{ top: -1px; left: -1px; border-right: none; border-bottom: none; }}
        .panel-corner.tr {{ top: -1px; right: -1px; border-left: none; border-bottom: none; }}
        .panel-corner.bl {{ bottom: -1px; left: -1px; border-right: none; border-top: none; }}
        .panel-corner.br {{ bottom: -1px; right: -1px; border-left: none; border-top: none; }}
        
        .stat-value {{
            font-size: 2.2em;
            font-weight: bold;
            color: white;
            font-family: 'Rajdhani', sans-serif;
            margin-top: 10px;
        }}
        
        .chart-container {{
            grid-column: span 2;
            height: 300px;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        
        /* Tabs System */
        .tab-container {{
            margin-top: 40px;
        }}
        
        .tabs {{
            display: flex;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
        }}
        
        .tab {{
            padding: 15px 30px;
            cursor: pointer;
            font-weight: bold;
            color: var(--text-dim);
            text-transform: uppercase;
            border: 1px solid transparent;
            border-bottom: none;
            transition: all 0.3s;
            position: relative;
            background: rgba(0,0,0,0.2);
            margin-right: 5px;
        }}

        .tab:hover {{
            color: var(--neon-blue);
            background: rgba(0, 243, 255, 0.05);
        }}
        
        .tab.active {{
            color: var(--bg-dark);
            background: var(--neon-blue);
            border-color: var(--neon-blue);
            box-shadow: 0 0 15px rgba(0, 243, 255, 0.2);
        }}
        
        .tab-content {{
            display: none;
            animation: glitchFade 0.3s;
        }}
        
        .tab-content.active {{
            display: block;
        }}

        /* --- VULNERABILITY CARD DESIGN --- */
        .vuln-item {{
            background: var(--bg-panel);
            border: 1px solid var(--border-color);
            margin-bottom: 25px;
            position: relative;
            overflow: hidden;
        }}

        .vuln-item::before {{
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 4px;
        }}

        .vuln-CRITICAL::before {{ background: var(--neon-red); box-shadow: 2px 0 10px var(--neon-red); }}
        .vuln-HIGH::before {{ background: #ff8c00; box-shadow: 2px 0 10px #ff8c00; }}
        .vuln-MEDIUM::before {{ background: var(--neon-yellow); }}
        .vuln-LOW::before {{ background: var(--neon-blue); }}
        .vuln-INFO::before {{ background: var(--neon-green); }}

        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            background: rgba(255,255,255,0.03);
            border-bottom: 1px solid var(--border-color);
        }}

        .vuln-title {{
            font-size: 1.2em;
            font-weight: bold;
            color: white;
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        .vuln-id {{
            font-family: 'Rajdhani', sans-serif;
            color: var(--text-dim);
            font-size: 0.9em;
            border: 1px solid var(--border-color);
            padding: 2px 8px;
        }}

        .badge {{
            font-size: 0.8em;
            padding: 4px 12px;
            border-radius: 0;
            text-transform: uppercase;
            font-weight: bold;
            letter-spacing: 1px;
        }}
        
        .badge-CRITICAL {{ background: rgba(255, 0, 60, 0.2); color: var(--neon-red); border: 1px solid var(--neon-red); }}
        .badge-HIGH {{ background: rgba(255, 140, 0, 0.2); color: #ff8c00; border: 1px solid #ff8c00; }}
        .badge-MEDIUM {{ background: rgba(252, 238, 10, 0.2); color: var(--neon-yellow); border: 1px solid var(--neon-yellow); }}
        .badge-LOW {{ background: rgba(0, 243, 255, 0.2); color: var(--neon-blue); border: 1px solid var(--neon-blue); }}
        .badge-INFO {{ background: rgba(10, 255, 10, 0.2); color: var(--neon-green); border: 1px solid var(--neon-green); }}

        .vuln-body {{
            padding: 20px;
        }}

        .data-grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 20px;
        }}

        .field-group {{
            margin-bottom: 5px;
        }}

        .field-label {{
            color: var(--text-dim);
            font-size: 0.7em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
            display: block;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            padding-bottom: 2px;
            width: fit-content;
        }}

        .field-value {{
            color: var(--text-main);
            font-family: 'JetBrains Mono', monospace;
            word-break: break-all;
            line-height: 1.4;
        }}

        .url-box {{
            color: var(--neon-blue);
            text-decoration: none;
            border-bottom: 1px dashed var(--neon-blue);
            transition: all 0.3s;
            display: inline-block;
        }}
        .url-box:hover {{ background: rgba(0, 243, 255, 0.1); }}

        .code-block {{
            background: #000;
            border: 1px solid #333;
            padding: 15px;
            color: var(--neon-green);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            position: relative;
            border-left: 2px solid var(--neon-green);
        }}
        
        .code-block::before {{
            content: '$ PAYLOAD >';
            display: block;
            color: var(--text-dim);
            font-size: 0.7em;
            margin-bottom: 5px;
            user-select: none;
        }}

        /* Buttons */
        .action-buttons {{
            position: fixed;
            bottom: 30px;
            right: 30px;
            display: flex;
            gap: 15px;
            z-index: 100;
        }}
        
        .btn {{
            background: black;
            color: var(--neon-blue);
            border: 1px solid var(--neon-blue);
            padding: 12px 25px;
            font-family: 'JetBrains Mono', monospace;
            cursor: pointer;
            text-transform: uppercase;
            font-weight: bold;
            transition: all 0.3s;
            box-shadow: 0 0 10px rgba(0, 243, 255, 0.1);
        }}

        .btn:hover {{
            background: var(--neon-blue);
            color: black;
            box-shadow: 0 0 20px rgba(0, 243, 255, 0.4);
        }}

        .footer {{
            margin-top: 50px;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
            text-align: center;
            font-size: 0.8em;
            color: var(--text-dim);
            margin-bottom: 80px;
        }}
        
        .sys-status {{
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            color: var(--neon-green);
            margin-top: 20px;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}

        @keyframes glitchFade {{
            0% {{ opacity: 0; transform: translateY(10px); }}
            100% {{ opacity: 1; transform: translateY(0); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div>
                <h1>NullSpecter<span style="color:var(--neon-blue)">_OPS</span></h1>
                <div class="subtitle">>>> SYSTEM VULNERABILITY ASSESSMENT REPORT_v2.0</div>
            </div>
            <div class="header-stats">
                <div class="risk-badge risk-{self.report_data['scan_info']['risk_level']}">
                    {self.report_data['scan_info']['risk_level']} THREAT DETECTED
                </div>
                <div style="margin-top:10px; font-size: 0.8em; color: var(--text-dim);">
                    REF_ID: {self.report_data['metadata']['report_id']}
                </div>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="panel">
                <div class="panel-corner tl"></div><div class="panel-corner tr"></div>
                <div class="panel-corner bl"></div><div class="panel-corner br"></div>
                <h3><i class="fas fa-crosshairs"></i> Target System</h3>
                <div class="stat-value" style="font-size: 1.2em; word-break: break-all;">
                    {helpers.html_encode(self.report_data['scan_info']['target_url'])}
                </div>
                <div style="margin-top: 5px; font-size: 0.8em; color: var(--neon-green);">
                    [ONLINE] {self.report_data['scan_info']['scan_date']}
                </div>
            </div>
            
            <div class="panel">
                <div class="panel-corner tl"></div><div class="panel-corner tr"></div>
                <div class="panel-corner bl"></div><div class="panel-corner br"></div>
                <h3><i class="fas fa-bug"></i> Vectors Found</h3>
                <div class="stat-value" style="color: var(--neon-red);">
                    {self.report_data['statistics']['total_vulnerabilities']}
                </div>
                <div style="margin-top: 5px; font-size: 0.8em;">
                    Across {self.report_data['scan_info']['total_checks']} Modules
                </div>
            </div>
            
            <div class="panel">
                <div class="panel-corner tl"></div><div class="panel-corner tr"></div>
                <div class="panel-corner bl"></div><div class="panel-corner br"></div>
                <h3><i class="fas fa-shield-alt"></i> Integrity Score</h3>
                <div class="stat-value" style="color: var(--neon-blue);">
                    {self.report_data['statistics']['security_score']}<span style="font-size:0.5em">%</span>
                </div>
                <div style="margin-top: 5px; font-size: 0.8em;">
                    Grade Rating: <span style="font-weight:bold; color: white;">{self.report_data['statistics']['score_grade']}</span>
                </div>
            </div>
            
            <div class="panel">
                <div class="panel-corner tl"></div><div class="panel-corner tr"></div>
                <div class="panel-corner bl"></div><div class="panel-corner br"></div>
                <h3><i class="fas fa-stopwatch"></i> Execution Time</h3>
                <div class="stat-value">
                    {self.report_data['scan_info']['scan_duration']}
                </div>
            </div>
            
            <div class="panel chart-container" style="grid-column: span 4; height: 350px;">
                <div class="panel-corner tl"></div><div class="panel-corner tr"></div>
                <div class="panel-corner bl"></div><div class="panel-corner br"></div>
                <canvas id="severityChart"></canvas>
            </div>
        </div>
        
        <div class="tab-container">
            <div class="tabs">
                <div class="tab active" onclick="showTab('vulnerabilities')"><i class="fas fa-list"></i> DETECTED THREATS</div>
                <div class="tab" onclick="showTab('recommendations')"><i class="fas fa-medkit"></i> PROTOCOLS</div>
            </div>
            
            <div id="vulnerabilities" class="tab-content active">
                {"".join(self._generate_vulnerability_items())}
            </div>
            
            <div id="recommendations" class="tab-content">
                {"".join(self._generate_recommendation_items())}
            </div>
        </div>
        
        <footer class="footer">
            <p>NULLSPECTER SECURITY OPS // CONFIDENTIAL // AUTHORIZED PERSONNEL ONLY</p>
            <p style="opacity: 0.5; margin-top: 5px;">Generated by NullSpecter v{self.report_data['metadata']['version']}</p>
            <div class="sys-status">
                <i class="fas fa-circle" style="font-size:0.6em;"></i> SYSTEM DIAGNOSTIC COMPLETE
            </div>
        </footer>
    </div>
    
    <div class="action-buttons">
        <button class="btn" onclick="window.print()"><i class="fas fa-print"></i> PRINT REPORT</button>
        <button class="btn" onclick="exportReport()"><i class="fas fa-file-export"></i> EXPORT JSON</button>
    </div>
    
    <script>
        // Matrix-themed Chart
        Chart.defaults.color = '#6c7a89';
        Chart.defaults.font.family = "'JetBrains Mono', monospace";
        
        const ctx = document.getElementById('severityChart').getContext('2d');
        const severityChart = new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                datasets: [{{
                    label: 'VULNERABILITY COUNT',
                    data: [
                        {self.report_data['statistics']['severity_distribution']['CRITICAL']},
                        {self.report_data['statistics']['severity_distribution']['HIGH']},
                        {self.report_data['statistics']['severity_distribution']['MEDIUM']},
                        {self.report_data['statistics']['severity_distribution']['LOW']},
                        {self.report_data['statistics']['severity_distribution']['INFO']}
                    ],
                    backgroundColor: [
                        'rgba(255, 0, 60, 0.7)',
                        'rgba(255, 140, 0, 0.7)',
                        'rgba(252, 238, 10, 0.7)',
                        'rgba(0, 243, 255, 0.7)',
                        'rgba(46, 204, 113, 0.7)'
                    ],
                    borderColor: [
                        '#ff003c',
                        '#ff8c00',
                        '#fcee0a',
                        '#00f3ff',
                        '#2ecc71'
                    ],
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        grid: {{ color: 'rgba(255, 255, 255, 0.05)' }}
                    }},
                    x: {{
                        grid: {{ display: false }}
                    }}
                }}
            }}
        }});
        
        function showTab(tabName) {{
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.getElementById(tabName).classList.add('active');
            event.currentTarget.classList.add('active');
        }}
        
        function exportReport() {{
            const reportData = {json_safe};
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", "{self.report_data['metadata']['report_id']}.json");
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        }}
    </script>
</body>
</html>
        """
    
    def _generate_vulnerability_items(self) -> List[str]:
        """Generate Professional Hacker-themed HTML for vulnerability items"""
        items = []
        
        for i, vuln in enumerate(self.report_data['vulnerabilities'], 1):
            severity = vuln.get('severity', 'INFO').upper()
            
            # Construct Payload HTML (Handles empty payloads gracefully)
            payload_html = ""
            if vuln.get('payload'):
                payload_html = f"""
                <div class="field-group" style="grid-column: span 2;">
                    <span class="field-label" style="color:var(--neon-green)">INJECTED PAYLOAD VECTOR</span>
                    <div class="code-block">{helpers.html_encode(vuln.get('payload'))}</div>
                </div>
                """
            # Construct Evidence HTML (For findings like subdomains or secrets)
            elif vuln.get('evidence'):
                payload_html = f"""
                <div class="field-group" style="grid-column: span 2;">
                    <span class="field-label" style="color:var(--neon-green)">EVIDENCE / PROOF</span>
                    <div class="code-block">{helpers.html_encode(vuln.get('evidence'))}</div>
                </div>
                """
            
            # Construct Parameter HTML
            param_html = ""
            if vuln.get('parameter'):
                param_html = f"""
                <div class="field-group">
                    <span class="field-label">AFFECTED PARAMETER</span>
                    <span class="field-value" style="color:var(--neon-yellow); font-weight:bold;">{helpers.html_encode(vuln.get('parameter'))}</span>
                </div>
                """

            items.append(f"""
                <div class="vuln-item vuln-{severity}">
                    <div class="vuln-header">
                        <div class="vuln-title">
                            <span class="vuln-id">#{i:03d}</span>
                            {helpers.html_encode(vuln.get('type', 'Unknown Threat'))}
                        </div>
                        <span class="badge badge-{severity}">{severity}</span>
                    </div>
                    
                    <div class="vuln-body">
                        <div class="data-grid">
                            <div class="field-group" style="grid-column: span 2;">
                                <span class="field-label">VULNERABLE ENDPOINT / TARGET</span>
                                <a href="{helpers.html_encode(vuln.get('url', '#'))}" target="_blank" class="field-value url-box" style="font-size: 1.1em;">{helpers.html_encode(vuln.get('url', 'N/A'))}</a>
                            </div>
                            
                            {param_html}
                            
                            <div class="field-group" style="grid-column: span 2;">
                                <span class="field-label">TECHNICAL DETAILS</span>
                                <div class="field-value" style="color: var(--text-dim); line-height: 1.5;">{helpers.html_encode(vuln.get('description', ''))}</div>
                            </div>
                            
                            {payload_html}
                        </div>
                    </div>
                </div>
            """)
        
        if not items:
            items.append('''
            <div class="panel" style="text-align:center; padding: 50px;">
                <i class="fas fa-shield-check" style="font-size: 3em; color: var(--neon-green); margin-bottom: 20px;"></i>
                <h2 style="color: var(--neon-green);">SYSTEM SECURE</h2>
                <p style="color: var(--text-dim);">No significant vulnerabilities detected during this scan operation.</p>
            </div>
            ''')
        
        return items
    
    def _generate_recommendation_items(self) -> List[str]:
        """Generate Hacker-themed HTML for recommendation items"""
        items = []
        
        for rec in self.report_data['recommendations']:
            items.append(f"""
                <div class="panel" style="margin-bottom: 20px;">
                    <div class="panel-corner tl"></div><div class="panel-corner tr"></div>
                    <div class="panel-corner bl"></div><div class="panel-corner br"></div>
                    <h3 style="color: white; border-bottom: 1px solid var(--border-color); padding-bottom: 15px; margin-bottom: 15px;">
                        <i class="fas fa-exclamation-triangle" style="color: var(--neon-yellow); margin-right: 10px;"></i> 
                        {rec.get('title', 'Recommendation')}
                    </h3>
                    <p style="margin-bottom: 20px; color: var(--text-main); line-height: 1.6;">{rec.get('description', '')}</p>
                    
                    <div style="background: rgba(0,0,0,0.3); padding: 20px; border-left: 3px solid var(--neon-blue);">
                        <strong style="color: var(--neon-blue); display:block; margin-bottom:15px; font-size: 0.9em; letter-spacing: 1px;">REMEDIATION PROTOCOL:</strong>
                        <ul style="list-style: none; padding-left: 0;">
                            {"".join(f"<li style='margin-bottom: 8px; display:flex; align-items:flex-start;'><i class='fas fa-check' style='color:var(--neon-green); margin-right:10px; margin-top:4px; font-size:0.8em;'></i><span>{step}</span></li>" for step in rec.get('remediation', []))}
                        </ul>
                    </div>
                </div>
            """)
        
        return items
    
    def generate_pdf(self, html_file: str = None) -> Optional[str]:
        """Generate PDF version of report"""
        if not PDFKIT_AVAILABLE:
            logger.warning("PDFKit not available. Install with: pip install pdfkit")
            return None
        
        if not html_file:
            html_file = self.generate_report(open_in_browser=False)
        
        pdf_file = html_file.replace('.html', '.pdf')
        
        try:
            # We need to set options for dark mode print
            options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'no-outline': None,
                'enable-local-file-access': None,
                'print-media-type': None  # Force screen media type to keep dark theme
            }
            pdfkit.from_file(html_file, pdf_file, options=options)
            logger.info(f"PDF report generated: {pdf_file}")
            return pdf_file
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return None


class JSONReporter:
    """Generate structured JSON reports"""
    
    def __init__(self, scan_results: Dict):
        self.scan_results = scan_results
        self.timestamp = datetime.now()
    
    def generate_report(self, output_file: str = None, pretty: bool = True) -> str:
        """Generate JSON report"""
        if not output_file:
            output_file = f"nullspecter_report_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        
        # Ensure output directory exists
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        report = {
            "metadata": {
                "generator": "NullSpecter Security Scanner",
                "version": "2.0",
                "report_id": f"NSR-{self.timestamp.strftime('%Y%m%d-%H%M%S')}",
                "timestamp": self.timestamp.isoformat(),
                "format": "JSON"
            },
            "scan_summary": {
                "target": self.scan_results.get('target_url', ''),
                "scan_date": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "duration": self.scan_results.get('scan_duration', ''),
                "total_vulnerabilities": self.scan_results.get('total_vulnerabilities', 0),
                "risk_level": self.scan_results.get('risk_level', 'UNKNOWN'),
                "checkers_performed": self.scan_results.get('checkers_performed', []),
                "scan_id": self.scan_results.get('scan_id', '')
            },
            "statistics": {
                "critical": self.scan_results.get('statistics', {}).get('critical_count', 0),
                "high": self.scan_results.get('statistics', {}).get('high_count', 0),
                "medium": self.scan_results.get('statistics', {}).get('medium_count', 0),
                "low": self.scan_results.get('statistics', {}).get('low_count', 0),
                "total": self.scan_results.get('total_vulnerabilities', 0)
            },
            "vulnerabilities": self.scan_results.get('vulnerabilities', []),
            "recommendations": self._generate_recommendations(self.scan_results.get('vulnerabilities', [])),
            "scan_details": {
                "execution_stats": self.scan_results.get('stats', {}),
                "raw_data_available": True
            }
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(report, f, indent=4, ensure_ascii=False, default=str)
            else:
                json.dump(report, f, ensure_ascii=False, default=str)
        
        logger.info(f"JSON report generated: {output_file}")
        
        return output_file
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate recommendations for JSON report"""
        vuln_types = set(v['type'] for v in vulnerabilities)
        
        recommendations = []
        
        for vuln_type in vuln_types:
            recommendations.append({
                "type": vuln_type,
                "priority": "HIGH" if vuln_type in ['SQL Injection', 'XSS', 'IDOR', 'SSRF', 'Exposed Secret'] else "MEDIUM",
                "description": f"Remediate {vuln_type} vulnerabilities",
                "count": sum(1 for v in vulnerabilities if v['type'] == vuln_type)
            })
        
        return recommendations