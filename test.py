import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class ContentAnalyzer:
    def __init__(self):
        self.findings = []
        self.score = 0

    def analyze_content(self, content):
        soup = BeautifulSoup(content, 'html.parser')

        # Check for inline scripts
        inline_scripts = soup.find_all('script', src=False)
        if inline_scripts:
            self.findings.append(f"Inline scripts detected ({len(inline_scripts)}) - consider moving to external files")
            self.score -= len(inline_scripts)

        # Check for unsafe JavaScript practices
        unsafe_js_patterns = {
            r'document\.write': "Usage of document.write detected - potential XSS risk",
            r'eval\s*\(': "Usage of eval() detected - potential security risk",
            r'innerHTML\s*=': "Direct manipulation of innerHTML detected - potential XSS risk",
            r'on\w+\s*=': "Inline event handlers detected - consider using addEventListener",
        }

        for pattern, message in unsafe_js_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                self.findings.append(message)
                self.score -= 1

        # Check for proper output encoding
        if re.search(r"<[^>]*>.*&lt;script&gt;", content):
            self.score += 1
            self.findings.append("Evidence of HTML encoding in output - good practice")

        # Check for secure cookie attributes
        for cookie in soup.find_all('meta', attrs={'http-equiv': 'Set-Cookie'}):
            if 'secure' not in cookie.get('content', '').lower():
                self.findings.append("Insecure cookie detected - missing 'Secure' flag")
                self.score -= 1
            if 'httponly' not in cookie.get('content', '').lower():
                self.findings.append("Insecure cookie detected - missing 'HttpOnly' flag")
                self.score -= 1

        # Check for proper Content Security Policy
        csp_meta = soup.find('meta', attrs={'http-equiv': 'Content-Security-Policy'})
        if not csp_meta:
            self.findings.append("No Content Security Policy meta tag found - consider adding one")
            self.score -= 1
        else:
            csp_content = csp_meta.get('content', '')
            if "default-src 'none'" not in csp_content:
                self.findings.append("Weak Content Security Policy - consider using stricter rules")
                self.score -= 1

        # Check for external resources
        external_resources = soup.find_all(['script', 'link', 'img'], src=True) + soup.find_all('link', href=True)
        for resource in external_resources:
            src = resource.get('src') or resource.get('href')
            if src and not src.startswith(('//', 'https://')):
                self.findings.append(f"Insecure resource loading detected: {src}")
                self.score -= 1

        # Check for proper HTTPS usage
        if 'http://' in content:
            self.findings.append("HTTP protocol usage detected - consider upgrading to HTTPS")
            self.score -= 1

        return self.findings, self.score