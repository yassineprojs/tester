import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from xssSecure import XSSSecurityAnalyzer
from cookie import CookieSecurityAnalyzer
from serverLeakage import ServerInfoLeakageDetector
from sqlSecure import SQLInjectionChecker
from SSL_TLS import SSLTLSAnalyzer
import ssl
import re
from urllib.robotparser import RobotFileParser
import async_timeout

class AdvancedScanner:
    def __init__(self, url, max_depth=3, max_urls=100, concurrency=10, timeout=300):
        self.start_url = url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.concurrency = concurrency
        self.timeout = timeout
        self.visited_urls = set()
        self.urls_to_visit = asyncio.Queue()
        self.session = None
        self.vulnerabilities = []
        self.sql_injection_checker = None
        self.xss_scanner = None
        self.leakage_detector = None
        self.ssl_tls_analyzer = None
        self.scan_results = []
        self.total_score = 0
        self.robot_parser = None

    async def create_session(self):
        self.session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
        self.xss_scanner = XSSSecurityAnalyzer(self.session)
        self.leakage_detector = ServerInfoLeakageDetector(self.session)
        self.sql_injection_checker = SQLInjectionChecker(self.session)
        self.ssl_tls_analyzer = SSLTLSAnalyzer(self.session)
        self.cookie_analyser = CookieSecurityAnalyzer(self.session)
        await self.setup_robot_parser()

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def setup_robot_parser(self):
        self.robot_parser = RobotFileParser()
        robots_url = urljoin(self.start_url, '/robots.txt')
        try:
            async with self.session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    self.robot_parser.parse(content.splitlines())
                else:
                    print(f"No robots.txt found at {robots_url}")
        except Exception as e:
            print(f"Error fetching robots.txt: {e}")

    def is_allowed(self, url):
        if self.robot_parser:
            return self.robot_parser.can_fetch("*", url)
        return True

    async def crawl(self):
        await self.create_session()
        await self.urls_to_visit.put((self.start_url, 0))

        tasks = [asyncio.create_task(self.process_url()) for _ in range(self.concurrency)]
        
        try:
            async with async_timeout.timeout(self.timeout):
                await self.urls_to_visit.join()
        except asyncio.TimeoutError:
            print(f"Scan timed out after {self.timeout} seconds")
        finally:
            for task in tasks:
                task.cancel()
            
            await asyncio.gather(*tasks, return_exceptions=True)
            await self.close_session()

    async def process_url(self):
        while True:
            try:
                url, depth = await self.urls_to_visit.get()
                if url not in self.visited_urls and len(self.visited_urls) < self.max_urls and self.is_allowed(url):
                    self.visited_urls.add(url)
                    print(f"Scanning: {url}")
                    try:
                        content = await self.fetch_content(url)
                        if content is None:
                            print(f"Skipping {url} due to content fetch error")
                            continue
                        server_task = asyncio.create_task(self.leakage_detector.analyze(url))
                        xss_task = asyncio.create_task(self.xss_scanner.analyze(url, content))
                        ssl_tls_task = asyncio.create_task(self.ssl_tls_analyzer.analyze(url))
                        xss_results, leakage_results, ssl_tls_results = await asyncio.gather(xss_task, server_task, ssl_tls_task)

                        subsite_score = (
                            leakage_results.get('score', 0) +
                            xss_results.get('score', 0) +
                            ssl_tls_results.get('score', 0)
                        )
                        self.total_score += subsite_score
                        self.scan_results.append({
                            "url": url,
                            "ssl_tls_scan": ssl_tls_results,
                            "server_leakage": leakage_results,
                            "xss_scan": xss_results,
                            "subsite_score": subsite_score
                        })
                        if depth < self.max_depth:
                            await self.extract_links(url, content, depth + 1)
                    except Exception as e:
                        print(f"Error processing {url}: {e}")
            finally:
                self.urls_to_visit.task_done()

    async def fetch_content(self, url):
        try:
            async with self.session.get(url, timeout=10) as response:
                return await response.text()
        except Exception as e:
            print(f"Error fetching content from {url}: {e}")
            return None

    async def get_results(self):
        return {
            "scanned_pages": list(self.visited_urls),
            "scan_results": self.scan_results,
            "total_score": self.total_score
        }

    async def extract_links(self, base_url, content, depth):
        soup = BeautifulSoup(content, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            link = urljoin(base_url, a_tag['href'])
            if link.startswith(self.start_url) and link not in self.visited_urls and self.is_allowed(link):
                await self.urls_to_visit.put((link, depth))