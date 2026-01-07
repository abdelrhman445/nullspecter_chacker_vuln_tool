#!/usr/bin/env python3
"""
NullSpecter Scanner - Professional Web Vulnerability Scanner
Enhanced with Rich UI, Wordlists, Professional Reporting, Crawler, WAF Evasion & Notifications
"""

import asyncio
import sys
import argparse
import time
import signal
import os
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

# --- Import aiohttp for Telegram Notifications ---
try:
    import aiohttp
except ImportError:
    print("Error: 'aiohttp' library is required.")
    print("Please run: pip install aiohttp")
    sys.exit(1)

# --- Import Rich for Professional UI ---
try:
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.style import Style
    from rich.traceback import install as install_rich_traceback
    
    # Initialize Rich Console
    console = Console()
    install_rich_traceback() 
    
except ImportError:
    print("Error: 'rich' library is required for the professional interface.")
    print("Please run: pip install rich")
    sys.exit(1)

# --- Import Scanner Modules ---
try:
    # Core imports
    from core.config import ScannerConfig, LogLevel, ReportFormat
    from core.database import scan_db
    from core.engine import ScannerEngine
    
    # Import AdvancedCrawler from core
    try:
        from core.crawler import AdvancedCrawler
        CRAWLER_AVAILABLE = True
    except ImportError:
        CRAWLER_AVAILABLE = False

    # Utilities
    from utils.logger import logger
    from utils.reporter import HTMLReporter, JSONReporter
    
    # Optional UserAgentManager
    try:
        from utils.user_agents import UserAgentManager
        USER_AGENTS_AVAILABLE = True
    except ImportError:
        USER_AGENTS_AVAILABLE = False
    
    # PDF Support
    try:
        import pdfkit
        PDF_SUPPORT = True
    except ImportError:
        PDF_SUPPORT = False
    
except ImportError as e:
    console.print(Panel(f"[bold red]Critical Import Error:[/bold red] {e}\n\n[yellow]Make sure all dependencies are installed:[/yellow]\npip install -r requirements.txt", title="System Error", border_style="red"))
    sys.exit(1)


class NullSpecterScanner:
    """Main scanner class with Professional Rich UI"""
    
    def __init__(self):
        self.config = None
        self.results = []
        self.scan_start_time = None
        self.interrupted = False  # Flag to track interruption state
        
    def print_banner(self):
        """Print a cinematic ASCII banner"""
        banner_text = """
    ███╗   ██╗██╗   ██╗██╗     ███████╗██████╗ ███████╗████████╗███████╗██████╗ 
    ████╗  ██║██║   ██║██║     ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗
    ██╔██╗ ██║██║   ██║██║     ███████╗██████╔╝█████╗     ██║   █████╗  ██████╔╝
    ██║╚██╗██║██║   ██║██║     ╚════██║██╔═══╝ ██╔══╝     ██║   ██╔══╝  ██╔══██╗
    ██║ ╚████║╚██████╔╝███████╗███████║██║     ███████╗   ██║   ███████╗██║  ██║
    ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
        """
        
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_row(Text(banner_text, style="bold magenta"))
        grid.add_row(Text("Advanced Security Scanner v2.0 | Professional Edition", style="bold cyan"))
        grid.add_row(Text("🛡️  Ready to hunt vulnerabilities 🛡️", style="italic green"))
        
        panel = Panel(
            grid,
            style="bold blue",
            border_style="cyan",
            padding=(1, 2)
        )
        console.print(panel)
        print() 

    def print_status(self, message: str, status: str = "info"):
        """Print formatted status messages using Rich"""
        status_styles = {
            "info":   {"emoji": "ℹ️ ", "style": "bold blue"},
            "success": {"emoji": "✅", "style": "bold green"},
            "warning": {"emoji": "⚠️ ", "style": "bold yellow"},
            "error":   {"emoji": "❌", "style": "bold red"},
            "critical": {"emoji": "💀", "style": "bold white on red"},
        }
        s = status_styles.get(status, status_styles["info"])
        timestamp = datetime.now().strftime("%H:%M:%S")
        text = Text()
        text.append(f"[{timestamp}] ", style="dim white")
        text.append(f"{s['emoji']} ", style="default")
        text.append(message, style=s['style'])
        console.print(text)
    
    def print_vulnerability(self, vuln: Dict):
        """Render vulnerability in a sleek Panel"""
        severity_colors = {
            "CRITICAL": "bold white on red",
            "HIGH": "bold red",
            "MEDIUM": "bold yellow",
            "LOW": "bold blue",
            "INFO": "dim white",
        }
        
        severity = vuln.get('severity', 'LOW').upper()
        color_style = severity_colors.get(severity, "white")
        
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold white", width=12)
        grid.add_column(style="cyan")
        
        grid.add_row("URL:", vuln.get('url', 'N/A'))
        if 'parameter' in vuln:
            grid.add_row("Parameter:", f"[yellow]{vuln.get('parameter')}[/yellow]")
        if 'payload' in vuln:
            grid.add_row("Payload:", f"[magenta]{vuln.get('payload')}[/magenta]")
        grid.add_row("Confidence:", f"[green]{vuln.get('confidence', 'N/A')}[/green]")
        grid.add_row("Check Type:", vuln.get('type', 'Unknown'))
        
        content = [grid]
        
        if vuln.get('description'):
            content.append(Text("\nDescription:", style="bold underline"))
            content.append(Text(vuln.get('description'), style="white"))
            
        if vuln.get('evidence'):
            evidence = vuln.get('evidence', '')
            if not isinstance(evidence, str):
                evidence = str(evidence)
            evidence_str = evidence[:300] + "..." if len(evidence) > 300 else evidence
            content.append(Text("\nEvidence:", style="bold underline"))
            content.append(Text(evidence_str, style="italic dim"))
            
        if vuln.get('recommendation'):
            content.append(Text("\nRecommendation:", style="bold underline"))
            content.append(Text(vuln.get('recommendation'), style="green"))

        console.print(
            Panel(
                Group(*content),
                title=f"[{color_style}] {severity} DETECTED [/{color_style}]",
                border_style="red" if severity in ["CRITICAL", "HIGH"] else "blue",
                expand=False
            )
        )
    
    def print_summary(self, results: List[Dict]):
        """Print professional summary table"""
        total_scans = len(results)
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results)
        
        sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for result in results:
            for vuln in result.get('vulnerabilities', []):
                sev = vuln.get('severity', 'LOW').upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1

        table = Table(title="🛡️  Scan Execution Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right", style="bold white")
        
        table.add_row("Targets Scanned", str(total_scans))
        table.add_row("Total Vulnerabilities", str(total_vulns))
        table.add_row("Critical Issues", str(sev_counts['CRITICAL']), style="red" if sev_counts['CRITICAL'] > 0 else "dim")
        table.add_row("High Issues", str(sev_counts['HIGH']), style="red" if sev_counts['HIGH'] > 0 else "dim")
        table.add_row("Medium Issues", str(sev_counts['MEDIUM']), style="yellow" if sev_counts['MEDIUM'] > 0 else "dim")
        table.add_row("Low Issues", str(sev_counts['LOW']), style="blue" if sev_counts['LOW'] > 0 else "dim")
        table.add_row("Info / Recon", str(sev_counts['INFO']), style="white")
        
        if self.scan_start_time:
            duration = time.time() - self.scan_start_time
            table.add_row("Total Duration", f"{duration:.2f}s")

        console.print("\n")
        console.print(table, justify="center")
        console.print("\n")
    
    # --- Telegram Notification System ---
    async def send_telegram_report(self):
        """Send a summary report to Telegram"""
        token = getattr(self.config, 'telegram_token', None)
        chat_id = getattr(self.config, 'telegram_chat_id', None)
        
        if not token or not chat_id:
            return

        console.print(f"[bold cyan]Sending Telegram notification...[/bold cyan]")
        
        # Prepare Summary
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in self.results)
        sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        targets_str = ""
        
        for result in self.results:
            target = result.get('target_url', 'unknown')
            targets_str += f"- `{target}`\n"
            for vuln in result.get('vulnerabilities', []):
                sev = vuln.get('severity', 'LOW').upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1

        message = (
            f"🛡️ *NullSpecter Scan Report*\n\n"
            f"📅 *Date:* {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
            f"🌍 *Targets:*\n{targets_str}\n"
            f"📊 *Summary:*\n"
            f"🔴 Critical: {sev_counts['CRITICAL']}\n"
            f"🟠 High: {sev_counts['HIGH']}\n"
            f"🟡 Medium: {sev_counts['MEDIUM']}\n"
            f"🔵 Low: {sev_counts['LOW']}\n"
            f"⚪ Info: {sev_counts['INFO']}\n\n"
            f"🔎 *Total Found:* {total_vulns}"
        )
        
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status == 200:
                        console.print("[bold green]✓ Telegram notification sent![/bold green]")
                    else:
                        console.print(f"[bold red]❌ Failed to send Telegram msg: {resp.status}[/bold red]")
        except Exception as e:
            console.print(f"[bold red]❌ Telegram Error: {e}[/bold red]")

    async def load_wordlists(self):
        """Load wordlists with a visual spinner"""
        wordlist_dir = Path("./data/payloads")
        wordlist_dir.mkdir(parents=True, exist_ok=True)
        wordlists = ["xss.txt", "sqli.txt", "ssrf.txt", "open_redirect.txt"]
        
        with console.status("[bold cyan]Loading payload dictionaries...", spinner="dots"):
            loaded_count = 0
            for name in wordlists:
                path = wordlist_dir / name
                if path.exists():
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            _ = sum(1 for line in f)
                        loaded_count += 1
                        console.print(f"[green]✓[/green] Loaded module: [bold]{name}[/bold]")
                    except:
                        pass
                else:
                    console.print(f"[yellow]![/yellow] Missing module: {name} (using defaults)", style="dim")
                    
            if loaded_count > 0:
                console.print(f"[bold green]System Ready:[/bold green] {loaded_count} payload sets loaded.")
            else:
                console.print("[bold yellow]Warning:[/bold yellow] No external payload lists found. Using built-in defaults.")

    async def scan_target(self, target_url: str) -> Optional[Dict]:
        """Scan a target with a progress bar effect"""
        console.print(f"\n[bold cyan]Target:[/bold cyan] {target_url}")
        console.print(f"[dim]{'─' * 50}[/dim]")
        
        scan_result = None
        try:
            with console.status(f"[bold blue]Scanning {target_url}...[/bold blue]", spinner="earth"):
                scan_result = await run_scan(target_url, self.config)
            
            if scan_result:
                vulns = scan_result.get('vulnerabilities', [])
                if vulns:
                    console.print(f"[bold red]Found {len(vulns)} vulnerability(ies) or info items![/bold red]")
                    for vuln in vulns:
                        self.print_vulnerability(vuln)
                else:
                    console.print(f"[bold green]No vulnerabilities found on {target_url}[/bold green]")
                return scan_result
            
        except (KeyboardInterrupt, asyncio.CancelledError):
            raise # Propagate up to save
        except Exception as e:
            self.print_status(f"Error scanning {target_url}: {str(e)}", "error")
            if scan_result: return scan_result
        return None
    
    async def perform_crawling(self, initial_targets: List[str]) -> List[str]:
        """Perform crawling to discover more targets"""
        if not CRAWLER_AVAILABLE:
            self.print_status("AdvancedCrawler module not found in core.crawler", "warning")
            return initial_targets
            
        console.print("\n[bold magenta]🕷️  Starting Spider Mode...[/bold magenta]")
        
        all_targets = set(initial_targets)
        new_discovered = set()
        
        crawler = AdvancedCrawler(config=self.config)
        
        try:
            with console.status(f"[bold magenta]Crawling {len(initial_targets)} seed URL(s)...[/bold magenta]", spinner="bouncingBall"):
                for url in initial_targets:
                    if self.interrupted: break
                    
                    links = await crawler.crawl(url)
                    for link in links:
                        if link not in all_targets:
                            new_discovered.add(link)
                            all_targets.add(link)
        except (KeyboardInterrupt, asyncio.CancelledError):
            console.print("[yellow]! Crawling interrupted. Proceeding with found targets.[/yellow]")
            self.interrupted = True
        
        if new_discovered:
            console.print(f"[green]✓ Discovered {len(new_discovered)} new endpoints![/green]")
            if len(new_discovered) < 10:
                for link in new_discovered:
                    console.print(f"  - {link}", style="dim")
            else:
                console.print(f"  (Displaying first 5) - Use --verbose for all")
                for link in list(new_discovered)[:5]:
                    console.print(f"  - {link}", style="dim")
        else:
            console.print("[yellow]! No new endpoints discovered during crawling.[/yellow]")
            
        return list(all_targets)

    async def run(self, args):
        """Main execution flow"""
        self.print_banner()
        await self.load_wordlists()
        
        targets = await self.parse_arguments(args)
        if not targets:
            self.print_status("No targets specified. Use -h for help.", "error")
            return
        
        self.config = await self.load_configuration(args)
        
        # Crawling
        if args.crawl:
            try:
                targets = await self.perform_crawling(targets)
            except KeyboardInterrupt:
                self.interrupted = True
        
        if self.interrupted:
            pass
        else:
            self.scan_start_time = time.time()
            self.results = []
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task_id = progress.add_task(f"[cyan]Processing {len(targets)} targets...", total=len(targets))
                
                try:
                    for target in targets:
                        if self.interrupted: break
                        
                        progress.stop()
                        result = await self.scan_target(target)
                        
                        if result:
                            # Handle interrupted but saved partial results
                            if result.get('scan_id') == 'partial_interrupted':
                                valid_part = result.copy()
                                valid_part['scan_id'] = 'interrupted' 
                                self.results.append(valid_part)
                                self.interrupted = True
                                break
                            else:
                                self.results.append(result)
                                
                        progress.start()
                        progress.advance(task_id)
                except KeyboardInterrupt:
                    self.interrupted = True
        
        self.print_summary(self.results)
        
        # Actions to perform on finish (or interrupted with save)
        if not self.interrupted or self.results:
            if getattr(self.config, 'telegram_token', None):
                await self.send_telegram_report()
            
            await self.generate_reports(args)
            
            if args.stats:
                await self.show_statistics()
    
    async def parse_arguments(self, args) -> List[str]:
        targets = []
        if args.url:
            targets.append(args.url)
        elif args.file:
            path = Path(args.file)
            if path.exists():
                with open(path, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
                console.print(f"[green]✓ Loaded {len(targets)} targets from file[/green]")
            else:
                self.print_status(f"File not found: {args.file}", "error")
        elif args.targets:
            targets = args.targets
        return targets

    async def load_configuration(self, args) -> ScannerConfig:
        config = ScannerConfig()
        if args.config:
            if args.config.endswith(('.yaml', '.yml')):
                config = ScannerConfig.from_yaml(args.config)
            elif args.config.endswith('.json'):
                config = ScannerConfig.from_json(args.config)
            else:
                self.print_status(f"Unsupported config format: {args.config}", "error")
                sys.exit(1)
        
        if args.rate_limit: config.rate_limit = args.rate_limit
        if args.timeout: config.timeout = args.timeout
        if args.verbose: 
            config.verbose = True
            config.log_level = LogLevel.DEBUG
        if args.quiet: 
            config.quiet = True
            config.log_level = LogLevel.WARNING
        if args.output: config.output_dir = args.output
        if args.modules != 'all': config.default_checks = [m.strip() for m in args.modules.split(',')]
        if args.auth_token: config.auth_token = args.auth_token
        if args.cookie: config.cookies = {'Cookie': args.cookie}
        if args.header:
            for h in args.header:
                if ':' in h:
                    key, value = h.split(':', 1)
                    config.headers[key.strip()] = value.strip()
        
        if args.random_agent:
            if USER_AGENTS_AVAILABLE:
                random_ua = UserAgentManager.get_random()
                config.headers['User-Agent'] = random_ua
                self.print_status(f"Using Random User-Agent: {random_ua[:40]}...", "success")
            else:
                self.print_status("UserAgentManager not available", "warning")

        if args.tamper:
            setattr(config, 'tamper', True)
            self.print_status("WAF Evasion / Payload Tampering: ENABLED", "success")

        # --- TELEGRAM CONFIG ---
        if args.telegram_token and args.telegram_chat_id:
            setattr(config, 'telegram_token', args.telegram_token)
            setattr(config, 'telegram_chat_id', args.telegram_chat_id)
            self.print_status("Telegram Notifications: ENABLED", "success")

        # --- NEW: Shodan Key ---
        if args.shodan_key:
            setattr(config, 'shodan_api_key', args.shodan_key)
            self.print_status("Shodan Integration: ENABLED", "success")

        if args.proxy: config.proxy = args.proxy
        if args.threads: config.thread_pool_size = args.threads
        if args.depth: config.scan_depth = args.depth 
        
        is_valid, errors = config.validate()
        if not is_valid:
            self.print_status("Configuration errors:", "error")
            for error in errors:
                self.print_status(f"  - {error}", "error")
            sys.exit(1)
        return config

    async def generate_reports(self, args):
        """Generate reports with properly directed output"""
        if not self.results:
            console.print("[yellow]No results to save.[/yellow]")
            return
            
        console.print("\n[bold underline]Report Generation[/bold underline]")
        generated = []
        
        output_dir = Path(args.output)
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.print_status(f"Could not create output directory {args.output}: {e}", "error")
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        for i, result in enumerate(self.results):
            target_clean = result.get('target_url', 'target').replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '')
            target_clean = target_clean[:30]
            
            if args.report in ['html', 'all']:
                reporter = HTMLReporter(result)
                filename = f"scan_{target_clean}_{timestamp}_{i+1}.html"
                full_path = output_dir / filename
                try:
                    report_file = reporter.generate_report(output_file=str(full_path))
                    generated.append(f"HTML: {report_file}")
                except Exception as e:
                    self.print_status(f"Failed to generate HTML: {e}", "error")
                
            if args.report in ['json', 'all']:
                json_reporter = JSONReporter(result)
                filename = f"scan_{target_clean}_{timestamp}_{i+1}.json"
                full_path = output_dir / filename
                try:
                    json_file = json_reporter.generate_report(output_file=str(full_path))
                    generated.append(f"JSON: {json_file}")
                except Exception as e:
                    self.print_status(f"Failed to generate JSON: {e}", "error")
                
        for rep in generated:
            console.print(f"[green]✓ Generated:[/green] {rep}")

    async def show_statistics(self):
        stats = scan_db.get_statistics(30)
        table = Table(title="Database Statistics (30 Days)", show_header=False, box=None)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")
        overall = stats.get('overall', {})
        table.add_row("Total Scans Stored", str(overall.get('total_scans', 0)))
        table.add_row("Total Vulns Found", str(overall.get('total_vulns', 0)))
        table.add_row("Critical Vulns", str(overall.get('critical_vulns', 0)))
        console.print(Panel(table, title="Persistence Layer", border_style="blue"))


async def run_scan(target_url: str, config: ScannerConfig = None, scan_id: str = None) -> Dict:
    """Run security checks with Interruption Handling"""
    if config is None:
        config = ScannerConfig()
    
    logger.info(f"Starting scan: {target_url}")
    engine = ScannerEngine(config.__dict__)
    await engine.initialize()
    
    try:
        # Standard Scan
        scan_result = await engine.scan(target_url)
        
        result_dict = {
            "scan_id": getattr(scan_result, 'scan_id', 'unknown'),
            "target_url": getattr(scan_result, 'target', target_url),
            "scan_duration": f"{getattr(scan_result, 'duration', 0):.2f}s",
            "vulnerabilities": getattr(scan_result, 'vulnerabilities', []),
            "checkers_performed": getattr(scan_result, 'checkers_performed', []),
            "risk_level": getattr(scan_result, 'risk_level', 'UNKNOWN'),
            "statistics": getattr(scan_result, 'statistics', {})
        }
        return result_dict

    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.warning("\n⚠️ Scan interrupted! Attempting to salvage partial results...")
        
        # COLLECT PARTIAL RESULTS
        partial_vulns = []
        if hasattr(engine, 'checks'):
            for check in engine.checks:
                if hasattr(check, 'findings'):
                    partial_vulns.extend(check.findings)
        
        partial_result = {
            "scan_id": "partial_interrupted",
            "target_url": target_url,
            "scan_duration": "interrupted",
            "vulnerabilities": partial_vulns, 
            "checkers_performed": [],
            "risk_level": "UNKNOWN",
            "statistics": {"note": "Scan interrupted by user"}
        }
        return partial_result

    except Exception as e:
        logger.error(f"Error in scan: {e}")
        return {"error": str(e), "vulnerabilities": []}
    finally:
        await engine.shutdown()


def main():
    """Entry Point"""
    parser = argparse.ArgumentParser(
        description='NullSpecter - Professional Web Vulnerability Scanner',
        epilog="Powered by Python & Rich"
    )
    
    target_group = parser.add_argument_group('Target Specification')
    target_group.add_argument('-u', '--url', help='Target URL to scan')
    target_group.add_argument('-f', '--file', help='File containing list of URLs')
    target_group.add_argument('--targets', nargs='+', help='Multiple target URLs')
    
    target_group.add_argument('--crawl', action='store_true', help='Enable Spider Mode to crawl target for more links')
    
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument('-c', '--config', help='Configuration file (YAML/JSON)')
    config_group.add_argument('-m', '--modules', default='all', help='Modules to run')
    config_group.add_argument('--rate-limit', type=int, default=10, help='Requests per second')
    config_group.add_argument('--timeout', type=int, default=30, help='Request timeout')
    config_group.add_argument('--depth', type=int, default=2, help='Crawling depth (default: 2)')
    
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--auth-token', help='Bearer token')
    auth_group.add_argument('--cookie', help='Cookie header')
    auth_group.add_argument('--header', action='append', help='Additional headers')
    
    # NEW: Notification Arguments
    notify_group = parser.add_argument_group('Notifications')
    notify_group.add_argument('--telegram-token', help='Telegram Bot Token')
    notify_group.add_argument('--telegram-chat-id', help='Telegram Chat ID')

    # NEW: Reconnaissance Group
    recon_group = parser.add_argument_group('Reconnaissance')
    recon_group.add_argument('--shodan-key', help='Shodan API Key for passive recon')

    advanced_group = parser.add_argument_group('Advanced')
    advanced_group.add_argument('--proxy', help='Proxy URL')
    advanced_group.add_argument('--threads', type=int, default=50, help='Thread pool')
    advanced_group.add_argument('--save-responses', action='store_true', help='Save HTTP responses')
    advanced_group.add_argument('--random-agent', action='store_true', help='Use random User-Agent for scan')
    advanced_group.add_argument('--tamper', action='store_true', help='Use WAF evasion/tampering techniques for payloads')

    output_group = parser.add_argument_group('Output')
    output_group.add_argument('--report', choices=['html', 'json', 'pdf', 'all'], default='html')
    output_group.add_argument('-o', '--output', default='./reports')
    output_group.add_argument('-v', '--verbose', action='store_true')
    output_group.add_argument('--quiet', action='store_true')
    output_group.add_argument('--no-banner', action='store_true')
    
    db_group = parser.add_argument_group('Database')
    db_group.add_argument('--db', help='Database file path')
    db_group.add_argument('--export', help='Export scan results')
    db_group.add_argument('--stats', action='store_true', help='Show database statistics')
    
    args = parser.parse_args()
    
    if sys.version_info < (3, 7):
        console.print("[bold red]Error: Python 3.7+ required[/bold red]")
        sys.exit(1)
    
    scanner = NullSpecterScanner()
    
    # --- CLEAN EVENT LOOP HANDLING ---
    try:
        asyncio.run(scanner.run(args))
    except KeyboardInterrupt:
        # Ensure we catch any stray interrupt that wasn't caught inside run
        scanner.interrupted = True
    
    # --- CHECK STATE AND ASK TO SAVE ---
    if scanner.interrupted:
        console.print("\n\n[bold yellow]![/bold yellow] Scan interrupted by user")
        
        try:
            choice = input("\nDo you want to save the results found so far? (y/N): ").strip().lower()
            if choice == 'y':
                console.print("\n[bold blue]Generating reports for collected data...[/bold blue]")
                
                # --- NEW: Send notification on interrupted save too ---
                if getattr(scanner.config, 'telegram_token', None):
                    asyncio.run(scanner.send_telegram_report())

                # Run the report generation in a fresh loop
                asyncio.run(scanner.generate_reports(args))
                console.print("[bold green]✓ Done. Exiting.[/bold green]")
            else:
                console.print("[yellow]Exiting without saving.[/yellow]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[red]Exiting...[/red]")
            
    sys.exit(0)

if __name__ == "__main__":
    main()