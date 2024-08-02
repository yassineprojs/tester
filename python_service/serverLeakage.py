import aiohttp
import asyncio
import re
from urllib.parse import urlparse

class ServerInfoLeakageDetector:
    def __init__(self, session):
        self.session = session
        self.results = {
            'url': '',
            'score': 0,
            'findings': set(),
            'warnings': set(),
            'vulnerabilities': [],
            'details': {
                'headers': {},
                'server_info': {}
            }
        }

    def add_finding(self, finding):
        self.results['findings'].add(finding)

    def add_warning(self, warning):
        self.results['warnings'].add(warning)

    def add_vulnerability(self, vulnerability):
        self.results['vulnerabilities'].append(vulnerability)

    def update_score(self, value):
        self.results['score'] = max(0, min(10, self.results['score'] + value))

    def add_detail(self, category, key, value):
        self.results['details'][category][key] = value

    async def analyze(self, url):
        self.results['url'] = url
        try:
            async with self.session.get(url, allow_redirects=True, timeout=10) as response:
                self.analyze_headers(response.headers)
                content = await response.text()
                self.analyze_content(content)
                await self.analyze_error_pages()
                await self.perform_banner_grabbing()
                await self.check_dns_info()
        except Exception as e:
            self.add_detail('error', 'request_error', str(e))
        return self.generate_report()

    def analyze_headers(self, headers):
        sensitive_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Generator', 'X-Drupal-Cache', 'X-Varnish', 'Via'
        ]
        
        for header in sensitive_headers:
            if header in headers:
                self.add_detail('headers', header, headers[header])
                self.add_warning(f"Sensitive header found: {header}")
                self.update_score(1)

        if 'X-Frame-Options' not in headers:
            self.add_warning("X-Frame-Options header is missing")
            self.update_score(0.25)
        
        if 'Strict-Transport-Security' not in headers:
            self.add_warning("HSTS header is missing")
            self.update_score(0.25)

        if 'X-XSS-Protection' not in headers:
            self.add_warning("X-XSS-Protection header is missing")
            self.update_score(0.25)

        if 'X-Content-Type-Options' not in headers:
            self.add_warning("X-Content-Type-Options header is missing")
            self.update_score(0.25)

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
                self.add_detail('server_info', key, matches)
                self.add_warning(f"Potential information leakage: {key}")
                self.update_score(1)

    async def analyze_error_pages(self):
        error_urls = [
            f"{self.results['url']}/nonexistent_page_12345",
            f"{self.results['url']}/index.php?id='",
            f"{self.results['url']}/index.asp?id=1/0"
        ]

        for url in error_urls:
            try:
                async with self.session.get(url, allow_redirects=False, timeout=5) as response:
                    if response.status in [404, 500]:
                        content = await response.text()
                        self.analyze_content(content)
                        self.update_score(1)
            except aiohttp.ClientError:
                pass

    async def perform_banner_grabbing(self):
        parsed_url = urlparse(self.results['url'])
        try:
            reader, writer = await asyncio.open_connection(parsed_url.hostname, parsed_url.port or 80)
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {parsed_url.hostname}\r\n\r\n".encode())
            await writer.drain()
            banner = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            lines = banner_str.split('\r\n')
            self.add_detail('server_info', 'Banner Status', lines[0] if lines else 'Unknown')
            
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    self.add_detail('server_info', f'Banner {key}', value)
            
            if 'Banner Server' in self.results['details']['server_info']:
                server = self.results['details']['server_info']['Banner Server']
                self.add_warning(f"Server software version exposed: {server}")
                self.update_score(1) 
        except (asyncio.TimeoutError, ConnectionRefusedError):
            pass

    async def check_dns_info(self):
        parsed_url = urlparse(self.results['url'])
        try:
            ip_addresses = await asyncio.get_event_loop().getaddrinfo(
                parsed_url.hostname, None
            )
            ip = ip_addresses[0][4][0]
            self.add_detail('server_info', 'IP', ip)
            try:
                hostname, _, _ = await asyncio.get_event_loop().getnameinfo((ip, 0), 0)
                if hostname != parsed_url.hostname:
                    self.add_detail('server_info', 'Real hostname', hostname)
                    self.add_warning("Real hostname exposed through reverse DNS")
                    self.update_score(1)
            except Exception:
                pass
        except Exception:
            pass


    def generate_report(self):
        overall_assessment = "Low information leakage"
        if self.results['score'] >= 7:
            overall_assessment = "High information leakage - immediate action recommended"
        elif self.results['score'] >= 4:
            overall_assessment = "Moderate information leakage - improvements needed"

        return {
            "url": self.results['url'],
            "score": self.results['score'],
            "findings": list(self.results['findings']),
            "warnings": list(self.results['warnings']),
            "vulnerabilities": self.results['vulnerabilities'],
            "details": self.results['details'],
            "overall_assessment": overall_assessment
        }