import requests
from urllib.parse import urlparse
import re
from datetime import datetime, timedelta


class CookieSecurityAnalyzer:
    def __init__(self, session):
        self.session = session
        self.results = {}
        self.url = None


    async def analyze(self,url,cookies):
        self.url = url
        results = {
            'cookies': [],
            'security_score': 0
        }

        for cookie in cookies:
            cookie_info =await self.analyze_cookie(cookie)
            results['cookies'].append(cookie_info)
            results['security_score'] += self.get_security_score(cookie_info)
        return results

    async def analyze_cookie(self, cookie):
        cookie_info = {
            'name': cookie.key,
            'domain': cookie.get('domain', 'Not Set'),
            'path': cookie.get('path', '/'),
            'secure': cookie.get('secure', False),
            'httponly': cookie.get('httponly', False),
            'samesite': self.get_samesite(cookie),
            'expires': self.format_expires(cookie),
            'max_age': cookie.get('max-age', 'Not Set'),
            'warnings': []
        }

        await self.check_secure_flag(cookie_info)
        await self.check_httponly_flag(cookie_info)
        await self.check_samesite(cookie_info)
        await self.check_expiration(cookie_info)
        await self.check_path(cookie_info)
        await self.check_domain(cookie_info)
        await self.check_for_sensitive_data(cookie_info)
        return cookie_info


    def get_samesite(self, cookie):
        samesite = cookie.get_nonstandard_attr('SameSite')
        return samesite if samesite else 'Not Set'

    def format_expires(self, cookie):
        if cookie.expires:
            return datetime.fromtimestamp(cookie.expires).isoformat()
        return 'Session Cookie'

    async def check_secure_flag(self, cookie_info):
        if not cookie_info['secure']:
            cookie_info['warnings'].append("Cookie is not marked as Secure")

    async def check_httponly_flag(self, cookie_info):
        if not cookie_info['httponly']:
            cookie_info['warnings'].append("Cookie is not marked as HttpOnly")

    async def check_samesite(self, cookie_info):
        if cookie_info['samesite'] == 'Not Set':
            cookie_info['warnings'].append("SameSite attribute is not set")
        elif cookie_info['samesite'].lower() not in ['strict', 'lax', 'none']:
            cookie_info['warnings'].append(f"Invalid SameSite value: {cookie_info['samesite']}")

    async def check_expiration(self, cookie_info):
        if cookie_info['expires'] != 'Session Cookie':
            try:
                expires = datetime.fromisoformat(cookie_info['expires'])
                if expires > datetime.now() + timedelta(days=365):
                    cookie_info['warnings'].append("Cookie expiration is set too far in the future")
            except ValueError:
                cookie_info['warnings'].append("Invalid expiration date format")

    async def check_path(self, cookie_info):
        if cookie_info['path'] == '/' or cookie_info['path'] == '':
            cookie_info['warnings'].append("Cookie path is set to root, which may be overly broad")

    async def check_domain(self, cookie_info):
        domain = urlparse(self.url).netloc
        if cookie_info['domain'].startswith('.'):
            if not domain.endswith(cookie_info['domain'][1:]):
                cookie_info['warnings'].append("Cookie domain may allow unintended subdomains")
        elif cookie_info['domain'] != domain and cookie_info['domain'] != 'Not Set':
            cookie_info['warnings'].append("Cookie domain does not match the current domain")


    async def check_for_sensitive_data(self, cookie_info):
        sensitive_patterns = [
            r'\bpassword\b',
            r'\bsessid\b',
            r'\bsession_id\b',
            r'\btoken\b',
            r'\bauth\b',
            r'\bapi_key\b',
        ]
        for pattern in sensitive_patterns:
            if re.search(pattern, cookie_info['name'], re.IGNORECASE):
                cookie_info['warnings'].append(f"Cookie name may contain sensitive data: {cookie_info['name']}")
                break

    def get_security_score(self,cookie_info):
        score = 0
        if not cookie_info['secure']:
            score += 2
        if not cookie_info['httponly']:
            score += 2
        if cookie_info['samesite'] == 'Not Set':
            score += 1
        score += len(cookie_info['warnings']) * 0.5
        return score

