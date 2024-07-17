import requests
import re
from urllib.parse import urlparse
import socket

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
        try:
            async with self.session.get(url, allow_redirects=True, timeout=10) as response:
                self.analyze_headers(response.headers)
                self.analyze_content(response.text)
                self.analyze_error_pages()
                self.perform_banner_grabbing()
                self.check_dns_info()
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

    def analyze_error_pages(self):
        error_urls = [
            f"{self.url}/nonexistent_page_12345",
            f"{self.url}/index.php?id='",
            f"{self.url}/index.asp?id=1/0"
        ]

        for url in error_urls:
            try:
                response = requests.get(url, allow_redirects=False, timeout=5)
                if response.status_code in [404, 500]:
                    self.analyze_content(response.text)
            except requests.RequestException:
                pass

    def perform_banner_grabbing(self):
        parsed_url = urlparse(self.url)
        try:
            with socket.create_connection((parsed_url.hostname, parsed_url.port or 80), timeout=5) as sock:
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + parsed_url.hostname.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                self.results['server_info']['Banner'] = banner.strip()
                if 'Server:' in banner:
                    self.add_warning("Server software version exposed in banner")
        except (socket.error, socket.timeout):
            pass

    def check_dns_info(self):
        parsed_url = urlparse(self.url)
        try:
            ip = socket.gethostbyname(parsed_url.hostname)
            self.results['server_info']['IP'] = ip
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                if hostname != parsed_url.hostname:
                    self.results['server_info']['Real hostname'] = hostname
                    self.add_warning("Real hostname exposed through reverse DNS")
            except socket.herror:
                pass
        except socket.gaierror:
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