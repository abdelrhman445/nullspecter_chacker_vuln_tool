"""
Async HTTP client with rate limiting, retry, and proxy support
"""

import aiohttp
import asyncio
from typing import Dict, Optional, Any, Union
import time
import random
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import ssl
import certifi
from urllib.parse import urlparse

class CircuitBreaker:
    """Circuit breaker pattern implementation"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures = {}
        self.state = {}  # 'closed', 'open', 'half-open'
        
    def record_failure(self, url: str):
        """Record a failure for a URL"""
        parsed = urlparse(url)
        domain = parsed.netloc
        
        if domain not in self.failures:
            self.failures[domain] = {'count': 0, 'last_failure': time.time(), 'state': 'closed'}
        
        self.failures[domain]['count'] += 1
        self.failures[domain]['last_failure'] = time.time()
        
        if self.failures[domain]['count'] >= self.failure_threshold:
            self.failures[domain]['state'] = 'open'
            
    def record_success(self, url: str):
        """Record a success for a URL"""
        parsed = urlparse(url)
        domain = parsed.netloc
        
        if domain in self.failures:
            if self.failures[domain]['state'] == 'half-open':
                self.failures[domain]['state'] = 'closed'
                self.failures[domain]['count'] = 0
            elif self.failures[domain]['state'] == 'closed':
                self.failures[domain]['count'] = max(0, self.failures[domain]['count'] - 1)
                
    def allow_request(self, url: str) -> bool:
        """Check if request is allowed"""
        parsed = urlparse(url)
        domain = parsed.netloc
        
        if domain not in self.failures:
            return True
            
        failure_info = self.failures[domain]
        
        if failure_info['state'] == 'closed':
            return True
        elif failure_info['state'] == 'open':
            # Check if recovery timeout has passed
            if time.time() - failure_info['last_failure'] > self.recovery_timeout:
                failure_info['state'] = 'half-open'
                return True
            return False
        elif failure_info['state'] == 'half-open':
            return True
            
        return True

class RequestCache:
    """Simple request cache"""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache = {}
        self.hits = 0
        self.misses = 0
        
    def get(self, key: str):
        """Get item from cache"""
        if key in self.cache:
            self.hits += 1
            return self.cache[key]
        self.misses += 1
        return None
        
    def set(self, key: str, value: Any):
        """Set item in cache"""
        if len(self.cache) >= self.max_size:
            # Remove oldest item
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
        self.cache[key] = value

class AdvancedHTTPClient:
    """Advanced HTTP client for security testing"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=self.config.get("circuit_breaker_threshold", 5),
            recovery_timeout=self.config.get("circuit_breaker_timeout", 60)
        )
        self.cache = RequestCache(self.config.get("cache_size", 1000))
        self.cookies = {}
        self.metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'total_time': 0
        }
        
        # User-Agent rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "NullSpecter/1.0 (Security Scanner)"
        ]
        
        self.default_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        
        # Rate limiting
        self.rate_limit = self.config.get("rate_limit", 10)
        self.last_request_time = 0
        self.semaphore = asyncio.Semaphore(self.rate_limit)
        
    async def __aenter__(self):
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def start(self):
        """Initialize aiohttp session"""
        timeout = aiohttp.ClientTimeout(
            total=self.config.get("timeout", 30),
            connect=10,
            sock_read=20
        )
        
        # SSL context
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        if not self.config.get("verify_ssl", False):
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(
            limit=100,
            ssl=ssl_context,
            force_close=True,
            enable_cleanup_closed=True
        )
        
        # Set random user agent
        headers = self.default_headers.copy()
        headers["User-Agent"] = random.choice(self.user_agents)
        
        # Add custom headers from config
        if "headers" in self.config:
            headers.update(self.config["headers"])
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers
        )
    
    async def close(self):
        """Close aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
    )
    async def request(self, method: str, url: str, **kwargs) -> Any:
        """Make HTTP request with rate limiting and retry"""
        
        # Check circuit breaker
        if not self.circuit_breaker.allow_request(url):
            class CircuitBreakerErrorResponse:
                status = 0
                text = "Circuit breaker is open"
                headers = {}
                circuit_breaker_open = True
            return CircuitBreakerErrorResponse()
        
        # Rate limiting
        await self._respect_rate_limit()
        
        # Add random delay if configured
        if self.config.get("random_delay", True):
            delay = random.uniform(
                self.config.get("delay_min", 0.1),
                self.config.get("delay_max", 1.0)
            )
            await asyncio.sleep(delay)
        
        # Prepare headers
        headers = kwargs.pop("headers", {})
        all_headers = {**self.default_headers, **headers}
        
        # Rotate User-Agent
        all_headers["User-Agent"] = random.choice(self.user_agents)
        
        # Prepare cookies
        cookies = kwargs.pop("cookies", {})
        all_cookies = {**self.cookies, **cookies}
        
        # Check cache for GET requests
        cache_key = f"{method}:{url}:{str(kwargs)}"
        if method.upper() == "GET" and self.config.get("cache_responses", True):
            cached = self.cache.get(cache_key)
            if cached:
                return cached
        
        start_time = time.time()
        
        try:
            async with self.semaphore:
                response = await self.session.request(
                    method=method.upper(),
                    url=url,
                    headers=all_headers,
                    cookies=all_cookies,
                    ssl=False if not self.config.get("verify_ssl", False) else None,
                    allow_redirects=self.config.get("follow_redirects", True),
                    max_redirects=self.config.get("max_redirects", 10),
                    **kwargs
                )
                
                # Read response text
                text = await response.text(errors='ignore')
                
                # Update metrics
                request_time = time.time() - start_time
                self.metrics['total_requests'] += 1
                self.metrics['total_time'] += request_time
                
                if response.status < 400:
                    self.metrics['successful_requests'] += 1
                    self.circuit_breaker.record_success(url)
                else:
                    self.metrics['failed_requests'] += 1
                    if response.status >= 500:
                        self.circuit_breaker.record_failure(url)
                
                # Create enhanced response object
                class EnhancedResponse:
                    def __init__(self, status, text, headers, request_time):
                        self.status = status
                        self.text = text
                        self.headers = dict(headers)
                        self.request_time = request_time
                        self.content_length = len(text)
                        self.ok = status < 400
                
                enhanced_response = EnhancedResponse(response.status, text, response.headers, request_time)
                
                # Cache GET responses
                if method.upper() == "GET" and self.config.get("cache_responses", True):
                    self.cache.set(cache_key, enhanced_response)
                
                return enhanced_response
                
        except Exception as e:
            # Update metrics
            self.metrics['total_requests'] += 1
            self.metrics['failed_requests'] += 1
            
            # Record circuit breaker failure
            self.circuit_breaker.record_failure(url)
            
            # Return error response
            class ErrorResponse:
                status = 0
                text = f"Request failed: {str(e)}"
                headers = {}
                request_time = time.time() - start_time
                ok = False
            
            return ErrorResponse()
    
    async def _respect_rate_limit(self):
        """Ensure rate limit is respected"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < (1.0 / self.rate_limit):
            await asyncio.sleep((1.0 / self.rate_limit) - time_since_last)
        
        self.last_request_time = time.time()
    
    def update_headers(self, headers: Dict[str, str]):
        """Update default headers"""
        self.default_headers.update(headers)
    
    def set_auth_token(self, token: str, token_type: str = "Bearer"):
        """Set authorization token"""
        self.default_headers["Authorization"] = f"{token_type} {token}"
    
    def set_cookie(self, name: str, value: str):
        """Set a cookie"""
        self.cookies[name] = value
    
    def get_metrics(self) -> Dict:
        """Get request metrics"""
        avg_time = self.metrics['total_time'] / self.metrics['total_requests'] if self.metrics['total_requests'] > 0 else 0
        success_rate = (self.metrics['successful_requests'] / self.metrics['total_requests'] * 100) if self.metrics['total_requests'] > 0 else 0
        
        return {
            **self.metrics,
            'average_request_time': avg_time,
            'success_rate': success_rate,
            'cache_hits': self.cache.hits,
            'cache_misses': self.cache.misses,
            'cache_hit_rate': (self.cache.hits / (self.cache.hits + self.cache.misses) * 100) if (self.cache.hits + self.cache.misses) > 0 else 0
        }
    
    async def test_connection(self, url: str) -> bool:
        """Test connection to URL"""
        try:
            response = await self.request("GET", url, timeout=5)
            return response.status < 400
        except:
            return False