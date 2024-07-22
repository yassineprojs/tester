import asyncio #For asynchronous programming
import aiohttp #For making asynchronous HTTP requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse #For URL manipulation
from xssSecure import XSSSecurityAnalyzer
from cookie import CookieSecurityAnalyzer
from serverLeakage import ServerInfoLeakageDetector
from sqlSecure import SQLInjectionChecker
from SSL_TLS import SSLTLSAnalyzer

class AdvancedScanner:
    def __init__(self, url, max_depth=3, max_urls=100, concurrency=10):
        self.start_url = url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.concurrency = concurrency
        self.visited_urls = set()
        self.urls_to_visit = asyncio.Queue()
        self.session = None
        self.vulnerabilities=[]
        self.sql_injection_checker = None
        self.xss_scanner = None
        self.cookie_scanner = None
        self.scan_results = []
        self.total_score = 0




    async def create_session(self):
        self.session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
        self.xss_scanner = XSSSecurityAnalyzer(self.session)
        self.cookie_scanner = CookieSecurityAnalyzer(self.session)
        # self.cookie_analyzer = CookieSecurityAnalyzer(self.session)
        # self.server_leakage_detector = ServerInfoLeakageDetector(self.session)
        # self.sql_injection_checker = SQLInjectionChecker(self.start_url)
        # self.ssl_tls_analyzer = SSLTLSAnalyzer(self.session)


    async def close_session(self):
        if self.session:
            await self.session.close()

    async def crawl(self):
        await self.create_session()
        await self.urls_to_visit.put((self.start_url, 0))

        tasks = [asyncio.create_task(self.process_url()) for _ in range(self.concurrency)]
        await self.urls_to_visit.join()

        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)
        await self.close_session()

    async def process_url(self):
        while True:
            url, depth = await self.urls_to_visit.get()
            if url not in self.visited_urls and len(self.visited_urls) < self.max_urls:
                self.visited_urls.add(url)
                print(f"Scanning: {url}")
                try:
                    async with self.session.get(url, timeout=10) as response:
                        content = await response.text()
                        xss_results = await self.xss_scanner.analyze(url, content)
                        self.scan_results.append({
                            "url": url,
                            "scan_type": "XSS",
                            "score": xss_results.get('score', 0),
                            "findings": xss_results.get('findings', []),
                            "vulnerabilities": xss_results.get('vulnerabilities', [])
                        })
                        self.total_score += xss_results.get('score', 0)
                        if depth < self.max_depth:
                            await self.extract_links(url, content, depth + 1)
                except Exception as e:
                    print(f"Error processing {url}: {e}")
            self.urls_to_visit.task_done()

    async def extract_links(self, base_url, content, depth):
        soup = BeautifulSoup(content, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            link = urljoin(base_url, a_tag['href'])
            if link.startswith(self.start_url) and link not in self.visited_urls:
                await self.urls_to_visit.put((link, depth))

    async def check_vulnerabilities(self, url, content,cookies):
        # Analyze cookies
        # cookie_results = await self.cookie_analyzer.analyze(url,cookies)
        # self.vulnerabilities.append(cookie_results)
        # xss analysis
        xss_results = await self.xss_scanner.analyze(url, content)
        self.vulnerabilities.extend(xss_results)
        # Server leakage analysis
    #     server_leakage_results = await self.server_leakage_detector.analyze(url)
    #     self.vulnerabilities.append(server_leakage_results)
    #     # SQL Injection analysis
    #     sql_injection_results = await self.run_sql_injection_check(url)
    #     self.vulnerabilities.append(sql_injection_results)
    #     # SSl/TLS analysis
    #     ssl_tls_results= await self.ssl_tls_analyzer.analyze(url)
    #     self.vulnerabilities.append(ssl_tls_results)

    # async def run_sql_injection_check(self, url):
    #         self.sql_injection_checker.base_url = url
    #         self.sql_injection_checker.session = self.session
    #         return await self.sql_injection_checker.analyze()
