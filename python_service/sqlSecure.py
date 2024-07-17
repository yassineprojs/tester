import requests
import re
from urllib.parse import urljoin, parse_qs, urlparse

class SQLInjectionChecker:
    def __init__(self, base_url):
        self.base_url = base_url
        self.results = {
            'vulnerable_parameters': [],
            'warnings': [],
            'vulnerability_score': 0
        }
        self.session = None

    async def analyze(self):
        if not self.session:
            raise ValueError("Session not set. Please set the session before analysis.")
        try:
            await self.find_input_points()
            await self.test_input_points()
            self.calculate_vulnerability_score()
        except Exception as e:
            self.results['error'] = f"Request Error: {str(e)}"
        return self.results

    async def find_input_points(self):
        async with self.session.get(self.base_url) as response:
            html = await response.text()
            self.results['input_points'] = {
                'forms': self.extract_forms(html),
                'get_params': self.extract_get_params(str(response.url))
            }


    async def extract_forms(self, html):
        form_pattern = re.compile(r'<form.*?action=["\']([^"\']*)["\'].*?>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<input.*?name=["\']([^"\']*)["\']', re.IGNORECASE)
        
        forms = []
        for form_match in form_pattern.finditer(html):
            action = form_match.group(1)
            inputs = input_pattern.findall(form_match.group(2))
            forms.append({'action': action, 'inputs': inputs})
        return forms

    async def extract_get_params(self, url):
        parsed_url = urlparse(url)
        return list(parse_qs(parsed_url.query).keys())

    async def test_input_points(self):
        for form in self.results['input_points']['forms']:
            await self.test_form(form)
        
        for param in self.results['input_points']['get_params']:
            await self.test_get_param(param)

    async def test_form(self, form):
        action_url = urljoin(self.base_url, form['action'])
        for input_name in form['inputs']:
            payloads = self.generate_sql_payloads(input_name)
            for payload in payloads:
                data = {input_name: payload}
                async with self.session.post(action_url, data=data) as response:
                    content = await response.text()
                    if self.check_sql_error(content):
                        self.add_vulnerability(f"Form input '{input_name}' in {action_url}")
                        break

    async def test_get_param(self, param):
        payloads = self.generate_sql_payloads(param)
        for payload in payloads:
            url = f"{self.base_url}?{param}={payload}"
            async with self.session.get(url) as response:
                content = await response.text()
                if self.check_sql_error(content):
                    self.add_vulnerability(f"GET parameter '{param}' in {self.base_url}")
                    break

    def generate_sql_payloads(self, param):
        return [
            f"' OR '1'='1",
            f'" OR "1"="1',
            f"' UNION SELECT NULL--",
            f"1 OR 1=1",
            f"1' ORDER BY 1--",
            f"1' AND '1'='1",
            f"{param}' AND '1'='1",
            f"1; DROP TABLE users--",
        ]

    def check_sql_error(self, content):
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"SQL syntax.*MariaDB server",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"SQLITE_ERROR",
            r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            r"\[SQL Server\]",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"com.jnetdirect.jsql",
            r"macromedia\.jdbc\.sqlserver",
            r"com\.informix\.jdbc",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*"
        ]
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in error_patterns)

    def add_vulnerability(self, description):
        if description not in self.results['vulnerable_parameters']:
            self.results['vulnerable_parameters'].append(description)
            self.add_warning(f"Potential SQL Injection vulnerability found: {description}")

    def add_warning(self, warning):
        if warning not in self.results['warnings']:
            self.results['warnings'].append(warning)

    def calculate_vulnerability_score(self):
        score = len(self.results['vulnerable_parameters']) * 2
        self.results['vulnerability_score'] = min(score, 10)  # Cap the score at 10