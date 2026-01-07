"""
Advanced Web Crawler Module for NullSpecter
Extracts links and endpoints from target pages using intelligent crawling.
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse
from typing import Set, List, Dict
import aiohttp

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

class AdvancedCrawler:
    """Intelligent web crawler to discover attack surfaces"""
    
    def __init__(self, config=None):
        """
        Initialize the crawler with configuration.
        :param config: ScannerConfig object containing settings (headers, depth, etc.)
        """
        self.config = config
        self.max_depth = config.scan_depth if config else 2
        self.concurrency = 10  # Max concurrent requests
        self.headers = config.headers if config else {}
        self.cookies = config.cookies if config else {}
        self.proxy = config.proxy if config else None
        
        self.visited: Set[str] = set()
        self.targets: Set[str] = set()
        self.scope_domain = ""

    async def get_links(self, session: aiohttp.ClientSession, url: str) -> Set[str]:
        """Fetch URL and extract links"""
        found_links = set()
        try:
            # Use configurations for request
            async with session.get(
                url, 
                headers=self.headers, 
                cookies=self.cookies,
                proxy=self.proxy,
                timeout=10, 
                ssl=False,
                allow_redirects=True
            ) as response:
                
                if response.status != 200:
                    return found_links
                
                # Check content type to avoid downloading binaries
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' not in content_type and 'application/xml' not in content_type:
                    return found_links

                html = await response.text()
                
                if not BS4_AVAILABLE:
                    # Regex fallback if BeautifulSoup is not installed
                    hrefs = re.findall(r'href=["\'](.*?)["\']', html)
                    srcs = re.findall(r'src=["\'](.*?)["\']', html)
                    actions = re.findall(r'action=["\'](.*?)["\']', html)
                    all_links = hrefs + srcs + actions
                else:
                    soup = BeautifulSoup(html, 'html.parser')
                    all_links = [a.get('href') for a in soup.find_all('a', href=True)]
                    all_links += [form.get('action') for form in soup.find_all('form', action=True)]
                    all_links += [script.get('src') for script in soup.find_all('script', src=True)]

                for link in all_links:
                    # Normalize URL
                    full_url = urljoin(url, link)
                    parsed = urlparse(full_url)
                    
                    # Remove fragments (#section)
                    full_url = parsed.scheme + "://" + parsed.netloc + parsed.path
                    if parsed.query:
                        full_url += "?" + parsed.query

                    # Only keep http/https links within scope
                    if parsed.scheme in ['http', 'https']:
                        # Scope Check: Must be same domain
                        if self.scope_domain in parsed.netloc:
                            found_links.add(full_url)
                        
        except Exception:
            pass
            
        return found_links

    async def crawl(self, start_url: str) -> List[str]:
        """Main crawl execution method"""
        if not BS4_AVAILABLE:
            print("Warning: beautifulsoup4 not installed. Crawling will be limited (Regex only).")
        
        # Set scope to the domain of the start URL
        self.scope_domain = urlparse(start_url).netloc
        self.targets.add(start_url)
        
        # Queue stores tuples of (url, current_depth)
        queue = [(start_url, 0)]
        
        async with aiohttp.ClientSession() as session:
            while queue:
                # Process in batches for concurrency
                current_batch = queue[:self.concurrency]
                queue = queue[self.concurrency:]
                
                tasks = []
                for url, depth in current_batch:
                    if url not in self.visited and depth < self.max_depth:
                        self.visited.add(url)
                        tasks.append(self.get_links(session, url))
                
                if tasks:
                    results = await asyncio.gather(*tasks)
                    for links in results:
                        for link in links:
                            if link not in self.visited and link not in self.targets:
                                self.targets.add(link)
                                queue.append((link, depth + 1))
        
        return list(self.targets)