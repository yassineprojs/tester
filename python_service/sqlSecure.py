import re
from urllib.parse import urljoin, parse_qs, urlparse

class SQLInjectionChecker:
    def __init__(self, session):
        self.session = session
        self.results = {
            'url': '',
            'score': 0,
            'findings': set(),
            'warnings': [],
            'vulnerabilities': [],
            'details': {
                'input_points': {
                    'forms': [],
                    'get_params': []
                }
            }
        }

    def add_finding(self, finding):
        self.results['findings'].add(finding)

    def add_warning(self, warning):
        self.results['warnings'].append(warning)

    def add_vulnerability(self, vulnerability):
        self.results['vulnerabilities'].append(vulnerability)

    def update_score(self, value):
        self.results['score'] += value

    def add_detail(self, category, key, value):
        if category not in self.results['details']:
            self.results['details'][category] = {}
        self.results['details'][category][key] = value

    async def analyze(self, url):
        self.results['url'] = url
        try:
            await self.find_input_points()
            await self.test_input_points()
            self.calculate_vulnerability_score()
        except Exception as e:
            self.add_detail('error', 'request_error', str(e))
        return self.generate_report()

    async def find_input_points(self):
        async with self.session.get(self.results['url']) as response:
            html = await response.text()
            self.results['details']['input_points'] = {
                'forms': await self.extract_forms(html),
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

    def extract_get_params(self, url):
        parsed_url = urlparse(url)
        return list(parse_qs(parsed_url.query).keys())

    async def test_input_points(self):
        for form in self.results['details']['input_points']['forms']:
            await self.test_form(form)
        
        for param in self.results['details']['input_points']['get_params']:
            await self.test_get_param(param)

    async def test_form(self, form):
        action_url = urljoin(self.results['url'], form['action'])
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
            url = f"{self.results['url']}?{param}={payload}"
            async with self.session.get(url) as response:
                content = await response.text()
                if self.check_sql_error(content):
                    self.add_vulnerability(f"GET parameter '{param}' in {self.results['url']}")
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

    def calculate_vulnerability_score(self):
        score = len(self.results['vulnerabilities']) * 2
        self.update_score(min(score, 10))  # Cap the score at 10

    def generate_report(self):
        overall_assessment = "No SQL Injection vulnerabilities detected"
        if self.results['score'] >= 7:
            overall_assessment = "Critical SQL Injection vulnerabilities detected - immediate action required"
        elif self.results['score'] >= 4:
            overall_assessment = "Potential SQL Injection vulnerabilities detected - further investigation needed"

        return {
            "url": self.results['url'],
            "score": self.results['score'],
            "findings": list(self.results['findings']),
            "warnings": self.results['warnings'],
            "vulnerabilities": self.results['vulnerabilities'],
            "details": self.results['details'],
            "overall_assessment": overall_assessment
        }