<div align="center">

# 🛡️ NullSpecter
### The Next-Gen Web Vulnerability Scanner & Red Teaming Framework

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![AsyncIO](https://img.shields.io/badge/Async-Powered-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Stable-success?style=for-the-badge)

<pre>
███╗   ██╗██╗   ██╗██╗     ███████╗██████╗ ███████╗████████╗███████╗██████╗ 
████╗  ██║██║   ██║██║     ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██╔██╗ ██║██║   ██║██║     ███████╗██████╔╝█████╗     ██║   █████╗  ██████╔╝
██║╚██╗██║██║   ██║██║     ╚════██║██╔═══╝ ██╔══╝     ██║   ██╔══╝  ██╔══██╗
██║ ╚████║╚██████╔╝███████╗███████║██║     ███████╗   ██║   ███████╗██║  ██║
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
</pre>

*An advanced, asynchronous security scanner designed for penetration testers, bug hunters, and red teamers who need speed, stealth, and intelligence.*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Supported Checks](#-supported-checks) • [Download](#-download)

</div>

---

## 🚀 Overview

**NullSpecter** is a high-performance vulnerability scanner built on a modern asynchronous architecture. Unlike traditional scanners, it employs intelligent crawling strategies to discover hidden API endpoints and utilizes advanced payload tampering techniques to bypass Web Application Firewalls (WAFs).

Whether you are performing a quick assessment or a full-scale Red Team engagement, NullSpecter provides the tools to find critical vulnerabilities fast.

## ✨ Key Features

### 🧠 Core Intelligence
- **Smart Spidering:** Goes beyond simple link scraping. Detects API patterns (REST/GraphQL), hidden endpoints, and dynamic parameters.
- **Fail-Safe Architecture:** Implements a **Circuit Breaker** pattern to handle network instability and prevent scanning hangs.
- **Graceful Interruption:** Never lose data again. NullSpecter auto-saves results and generates reports even if you stop the scan (Ctrl+C) mid-process.

### 🛡️ Stealth & Evasion
- **WAF Evasion Engine:** Built-in payload tampering capabilities (Double Encoding, SQL Comment Obfuscation, IP/Hex Obfuscation) to slip past firewalls.
- **Identity Rotation:** Automatically rotates `User-Agents` to mimic legitimate traffic and avoid IP blocking.

### ⚡ Performance
- **Fully Asynchronous:** Powered by `asyncio` and `aiohttp` to handle thousands of requests concurrently with minimal resource usage.
- **Database Persistence:** Uses SQLite to store scan history, allowing for pause/resume functionality and long-term data tracking.

### 📊 Professional Reporting
- **Enterprise Reports:** Generates detailed HTML & JSON reports featuring executive summaries, remediation steps, and vulnerability evidence.
- **Rich CLI:** A beautiful, hacker-themed terminal interface using the `rich` library for real-time feedback.

## 🎯 Supported Checks

| Vulnerability Module | Capabilities | Severity |
|----------------------|--------------|----------|
| **SQL Injection** | Error-based, Boolean-based, and Time-based Blind SQLi. | `CRITICAL` |
| **XSS** | Reflected and Stored Cross-Site Scripting detection. | `HIGH` |
| **SSRF** | Server-Side Request Forgery with internal IP obfuscation techniques. | `CRITICAL` |
| **IDOR** | Insecure Direct Object Reference detection in URL parameters. | `HIGH` |
| **Open Redirect** | Unvalidated redirects and forwards detection. | `MEDIUM` |
| **GraphQL** | Introspection analysis and batching attack detection. | `MEDIUM` |
| **Security Headers** | Missing or misconfigured HTTP security headers analysis. | `LOW` |

## 📥 Download & Installation

```bash
# 1. Clone the repository
git clone https://github.com/abdelrhman445/nullspecter_chacker_vuln_tool.git

# 2. Navigate to the directory
cd nullspecter_chacker_vuln_tool

# 3. Install dependencies
pip install -r requirements.txt
```

## 🛠️ Usage Examples

### 1. Basic Scan

Perform a quick scan on a single target URL.

```bash
python main.py -u "http://target-site.com"
```

### 2. Full Attack Mode (Red Team)

Enable Crawling, WAF Evasion, Random Agents, and generate an HTML report.

```bash
python main.py -u "http://target-site.com" --crawl --tamper --random-agent --report html
```

### 3. Mass Scanning

Scan a list of targets from a file with high concurrency.

```bash
python main.py -f targets.txt --threads 50 --output ./mass_reports
```

### 4. Authenticated Scan

Scan behind a login page using a session cookie or token.

```bash
python main.py -u "http://target-site.com/dashboard" --cookie "session_id=xyz123"
```

## ⚙️ Configuration Options

| Argument | Description |
| --- | --- |
| `-u`, `--url` | Target URL to scan. |
| `--crawl` | Enable the smart spider to discover new links and endpoints. |
| `--tamper` | Enable WAF evasion techniques (payload obfuscation). |
| `--random-agent` | Use random User-Agent strings for stealth. |
| `--report` | Report format (`html`, `json`, `all`). |
| `--depth` | Crawling depth (default: 2). |
| `--threads` | Number of concurrent threads (default: 50). |
| `--proxy` | Proxy URL (e.g., `http://127.0.0.1:8080` for Burp Suite). |

## 📂 Project Structure

```
NullSpecter/
├── checks/             # Vulnerability detection logic
├── core/               # Engine, Database, Crawler, Config
├── data/               # Wordlists and Payloads
├── reports/            # Output directory for reports
├── utils/              # Reporting and Logging utilities
└── main.py             # CLI Entry point
```

## ⚠️ Disclaimer

**NullSpecter** is a security tool created for **educational purposes and authorized penetration testing only**. The developers are not responsible for any misuse or illegal damage caused by this tool. Always obtain written permission before scanning any target.

---

<div align="center">
Made with ❤️ by <a href="https://www.google.com/search?q=https://github.com/abdelrhman445">Abdelrhman</a>
</div>
