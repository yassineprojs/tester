import aiohttp
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse, parse_qs

class XSSSecurityAnalyzer:
    def __init__(self, retry_client):
        self.scans = []
        self.total_score = 0
        self.retry_client = retry_client


    def add_finding(self, finding):
        self.results['findings'].add(finding)

    def add_warning(self, warning):
        self.results['warnings'].add(warning)

    def add_vulnerability(self, vulnerability):
        self.results['vulnerabilities'].append(vulnerability)

    def update_score(self, value):
        self.results['score'] += value

    def add_detail(self, category, key, value):
        if category not in self.results['details']:
            self.results['details'][category] = {}
        self.results['details'][category][key] = value

    async def analyze(self, url, content):
        self.results = {
            'url': url,
            'score': 0,
            'findings': set(),
            'warnings': set(),
            'vulnerabilities': [],
            'details': {}
        }
        
        await self.check_headers()
        self.analyze_content(content)
        self.check_forms(content)
        await self.check_reflected_xss(url, content)
        
        report = self.generate_report()
        self.scans.append(report)
        self.total_score += report['score']
        return report

    async def check_headers(self):
        async with self.retry_client.get(self.results['url']) as response:
            headers = response.headers
            self._check_content_security_policy(headers)
            self._check_strict_transport_security(headers)
            self._check_x_frame_options(headers)
            self._check_x_content_type_options(headers)
            self._check_referrer_policy(headers)
            self._check_feature_policy(headers)

    def _check_content_security_policy(self, headers):
        csp = headers.get('Content-Security-Policy')
        if csp:
            self.update_score(1)
            self.add_finding("CSP header present - good")
            self._analyze_csp(csp)
        else:
            self.add_warning("CSP header missing - consider implementing")

    def _analyze_csp(self, csp):
        directives = csp.split(';')
        for directive in directives:
            directive = directive.strip()
            if directive.startswith('default-src'):
                if "'none'" in directive:
                    self.update_score(1)
                    self.add_finding("CSP uses 'default-src: none' - strict policy")
                elif "'self'" in directive:
                    self.update_score(0.5)
                    self.add_finding("CSP uses 'default-src: self' - moderately strict")
            elif directive.startswith('script-src'):
                if "'unsafe-inline'" in directive or "'unsafe-eval'" in directive:
                    self.add_warning("CSP allows unsafe scripts - consider removing 'unsafe-inline' and 'unsafe-eval'")
                else:
                    self.update_score(1)
                    self.add_finding("CSP properly restricts script sources")

    def _check_strict_transport_security(self, headers):
        hsts = headers.get('Strict-Transport-Security')
        if hsts:
            self.update_score(1)
            self.add_finding("HSTS header present - good")
            if 'includeSubDomains' in hsts:
                self.update_score(0.5)
                self.add_finding("HSTS includes subdomains")
            if 'preload' in hsts:
                self.update_score(0.5)
                self.add_finding("HSTS preload ready")
            max_age = re.search(r'max-age=(\d+)', hsts)
            if max_age:
                age = int(max_age.group(1))
                if age >= 31536000:
                    self.update_score(0.5)
                    self.add_finding("HSTS max-age is at least one year")
                else:
                    self.add_warning(f"HSTS max-age is {age} seconds - consider increasing to at least one year")
        else:
            self.add_warning("HSTS header missing - consider implementing")

    def _check_x_frame_options(self, headers):
        x_frame_options = headers.get('X-Frame-Options')
        if x_frame_options:
            self.update_score(1)
            self.add_finding(f"X-Frame-Options header present: {x_frame_options}")
            if x_frame_options.upper() in ['DENY', 'SAMEORIGIN']:
                self.update_score(0.5)
                self.add_finding("X-Frame-Options properly set to prevent clickjacking")
        else:
            self.add_warning("X-Frame-Options header missing - consider implementing to prevent clickjacking")

    def _check_x_content_type_options(self, headers):
        x_content_type_options = headers.get('X-Content-Type-Options')
        if x_content_type_options:
            if x_content_type_options.lower() == 'nosniff':
                self.update_score(1)
                self.add_finding("X-Content-Type-Options header properly set to 'nosniff'")
            else:
                self.add_warning(f"X-Content-Type-Options header present but not set to 'nosniff': {x_content_type_options}")
        else:
            self.add_warning("X-Content-Type-Options header missing - consider implementing to prevent MIME type sniffing")

    def _check_referrer_policy(self, headers):
        referrer_policy = headers.get('Referrer-Policy')
        if referrer_policy:
            self.update_score(1)
            self.add_finding(f"Referrer-Policy header present: {referrer_policy}")
            if referrer_policy.lower() in ['no-referrer', 'strict-origin-when-cross-origin']:
                self.update_score(0.5)
                self.add_finding("Referrer-Policy set to a strict value")
        else:
            self.add_warning("Referrer-Policy header missing - consider implementing to control referrer information")

    def _check_feature_policy(self, headers):
        feature_policy = headers.get('Feature-Policy') or headers.get('Permissions-Policy')
        if feature_policy:
            self.update_score(1)
            self.add_finding("Feature-Policy/Permissions-Policy header present - good")
        else:
            self.add_warning("Feature-Policy/Permissions-Policy header missing - consider implementing to control browser features")

    def analyze_content(self, content):
        soup = BeautifulSoup(content, 'html.parser')

        inline_scripts = soup.find_all('script', src=False)
        if inline_scripts:
            self.add_warning(f"Inline scripts detected - consider moving to external files")
            self.update_score(-len(inline_scripts))

        unsafe_js_patterns = {
            r'document\.write': "Usage of document.write detected - potential XSS risk",
            r'eval\s*\(': "Usage of eval() detected - potential security risk",
            r'innerHTML\s*=': "Direct manipulation of innerHTML detected - potential XSS risk",
            r'on\w+\s*=': "Inline event handlers detected - consider using addEventListener",
            r'setTimeout\s*\(\s*[\'"`]': "Potentially unsafe use of setTimeout with string argument",
            r'setInterval\s*\(\s*[\'"`]': "Potentially unsafe use of setInterval with string argument",
        }

        for pattern, message in unsafe_js_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                self.add_warning(message)
                self.update_score(-1)

        if re.search(r"<[^>]*>.*&lt;script&gt;", content):
            self.update_score(1)
            self.add_finding("Evidence of HTML encoding in output - good practice")

    async def check_reflected_xss(self, url, content):
        payloads = self.generate_payloads()
        
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        for param, values in params.items():
            for payload in payloads:
                test_url = url.replace(f"{param}={values[0]}", f"{param}={payload}")
                async with self.retry_client.get(test_url) as response:
                    response_text = await response.text()
                    if payload in response_text:
                        self.add_vulnerability(f"Reflected XSS found in URL parameter {param} at {url}")

        soup = BeautifulSoup(content, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            await self.check_form_xss(url, form, payloads)
        
    async def check_form_xss(self, url, form, payloads):
        action = urljoin(url, form.get("action", ''))
        method = form.get('method', 'get').lower()
        for payload in payloads:
            data = {input.get('name'): payload for input in form.find_all('input') if input.get('name')}
            async with self.retry_client.request(method, action, data=data if method == 'post' else None, params=data if method == 'get' else None) as response:
                response_text = await response.text()
            if payload in response_text:
                self.add_vulnerability(f"Reflected XSS found in form at {url}")
                return 
 
    def check_forms(self, content):
        soup = BeautifulSoup(content, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            if not form.find('input', attrs={'type': 'hidden', 'name': re.compile(r'csrf', re.I)}):
                self.add_warning(f"Form {form.get('id', 'unknown')} lacks CSRF token - potential XSS risk")

    def generate_payloads(self):
        return [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'-alert('XSS')-'"
        ]
    
    def generate_report(self):
        overall_assessment = "Weak XSS protection - improvements recommended"
        if self.results['score'] >= 7:
            overall_assessment = "Strong XSS protection measures in place"
        elif self.results['score'] >= 4:
            overall_assessment = "Moderate XSS protection, but improvements needed"

        return {
            "url": self.results['url'],
            "score": self.results['score'],
            "findings": list(self.results['findings']),
            "warnings": list(self.results['warnings']),
            "vulnerabilities": self.results['vulnerabilities'],
            "details": self.results['details'],
            "overall_assessment": overall_assessment
        }