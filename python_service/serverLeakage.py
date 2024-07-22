import aiohttp
import asyncio
import re
from urllib.parse import urlparse

class ServerInfoLeakageDetector:
    def __init__(self, session):
        self.session = session
        self.results = {
            'headers': {},
            'server_info': {},
            'warnings': [],
            'leakage_score': 0
        }


    async def analyze(self,url):
        self.url = url
        try:
            async with self.session.get(url, allow_redirects=True, timeout=10) as response:
                self.analyze_headers(response.headers)
                content = await response.text()
                self.analyze_content(content)
                await self.analyze_error_pages()
                await self.perform_banner_grabbing()
                await self.check_dns_info()
                self.calculate_leakage_score()
        except Exception as e:
            self.results['error'] = f"Request Error: {str(e)}"
        return self.results

    def analyze_headers(self, headers):
        sensitive_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Generator', 'X-Drupal-Cache', 'X-Varnish', 'Via'
        ]
        
        for header in sensitive_headers:
            if header in headers:
                self.results['headers'][header] = headers[header]
                self.add_warning(f"Sensitive header found: {header}")

        if 'X-Frame-Options' not in headers:
            self.add_warning("X-Frame-Options header is missing")
        
        if 'Strict-Transport-Security' not in headers:
            self.add_warning("HSTS header is missing")

        if 'X-XSS-Protection' not in headers:
            self.add_warning("X-XSS-Protection header is missing")

        if 'X-Content-Type-Options' not in headers:
            self.add_warning("X-Content-Type-Options header is missing")

    def analyze_content(self, content):
        patterns = {
            'PHP version': r'PHP/[\d\.]+',
            'ASP.NET version': r'ASP\.NET Version:[\d\.]+',
            'Server path': r'[C-Z]:\\\\.*\.(?:aspx?|php|js)',
            'Stack trace': r'(?i)stack trace:',
            'SQL error': r'(?i)sql syntax.*mysql',
            'Database connection string': r'(?i)data source=.*;',
            'Email address': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }

        for key, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                self.results['server_info'][key] = matches
                self.add_warning(f"Potential information leakage: {key}")

    async def analyze_error_pages(self):
        error_urls = [
            f"{self.url}/nonexistent_page_12345",
            f"{self.url}/index.php?id='",
            f"{self.url}/index.asp?id=1/0"
        ]

        for url in error_urls:
            try:
                async with self.session.get(url, allow_redirects=False, timeout=5) as response:
                    if response.status in [404, 500]:
                        content = await response.text()
                        self.analyze_content(content)
            except aiohttp.ClientError:
                pass

    async def perform_banner_grabbing(self):
        parsed_url = urlparse(self.url)
        try:
            reader, writer = await asyncio.open_connection(parsed_url.hostname, parsed_url.port or 80)
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {parsed_url.hostname}\r\n\r\n".encode())
            await writer.drain()
            banner = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            # Parse the banner
            lines = banner_str.split('\r\n')
            parsed_banner = {
                'Status': lines[0] if lines else 'Unknown',
                'Headers': {}
            }
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    parsed_banner['Headers'][key] = value
            
            self.results['server_info']['Banner'] = parsed_banner
            
            if 'Server' in parsed_banner['Headers']:
                self.add_warning(f"Server software version exposed: {parsed_banner['Headers']['Server']}")
        except (asyncio.TimeoutError, ConnectionRefusedError):
            pass

    async def check_dns_info(self):
        parsed_url = urlparse(self.url)
        try:
            ip_addresses = await asyncio.get_event_loop().getaddrinfo(
                parsed_url.hostname, None
            )
            ip = ip_addresses[0][4][0]
            self.results['server_info']['IP'] = ip
            try:
                hostname, _, _ = await asyncio.get_event_loop().getnameinfo((ip, 0), 0)
                if hostname != parsed_url.hostname:
                    self.results['server_info']['Real hostname'] = hostname
                    self.add_warning("Real hostname exposed through reverse DNS")
            except Exception:
                pass
        except Exception:
            pass

    def add_warning(self, warning):
        if warning not in self.results['warnings']:
            self.results['warnings'].append(warning)

    def calculate_leakage_score(self):
        score = 0
        score += len(self.results['headers']) * 2
        score += len(self.results['server_info']) * 3
        score += len(self.results['warnings'])
        self.results['leakage_score'] = min(score, 10)  # Cap the score at 10