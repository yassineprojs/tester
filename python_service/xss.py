from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
import asyncio 
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import aiohttp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import numpy as np
from pyppeteer import launch
import random
import html



class XSSscanner:
    def __init__(self,session,visited_urls):
        self.session = session
        self.visited_urls = visited_urls
        self.vulnerabilities = []
        self.payload_generator = PayloadGenerator()
        self.browser = None

    async def initialize_browser(self):
        if not self.browser:
            self.browser = await launch(headless=True)

    async def close_browser(self):
        if self.browser:
            await self.browser.close()
            self.browser = None


    async def scan(self, url,content):
        try:
            await self.check_reflected_xss(url,content)
            await self.check_stored_xss(url,content)
            await self.check_dom_xss(url)
        except Exception as e:
            print(f"Error scanning {url} for XSS: {e}")

            

    async def check_dom_xss(self,url):
        if not self.browser:
            await self.initialize_browser()

        page = await self.browser.newPage()
        try:
            await page.goto(url, waitUntil='networkidle0')

            # Analyze JavaScript code
            scripts = await page.evaluate('''
                () => Array.from(document.scripts).map(script => script.innerHTML)
            ''')
            for script in scripts:
                if re.search(r'document\.write\(.*?\)', script) or re.search(r'\.innerHTML\s*=', script):
                    self.vulnerabilities.append(f'Potential DOM-based XSS found in {url}')
                    break

            # Check for dynamic DOM modifications
            payloads = self.payload_generator.generate_payloads()
            for payload in payloads:
                await page.goto(f"{url}#xss={payload}")
                content = await page.content()
                if payload in content:
                    self.vulnerabilities.append(f"DOM-based XSS found in {url}")
                    break

            # Test event handlers
            event_handlers = ['onload', 'onerror', 'onmouseover', 'onclick', 'onsubmit']
            for handler in event_handlers:
                payload = f"<img src=x {handler}=alert('XSS')>"
                await page.evaluate(f'''
                    () => {{
                        let div = document.createElement('div');
                        div.innerHTML = `{payload}`;
                        document.body.appendChild(div);
                    }}
                ''')
                
                # Check if the alert was triggered
                dialog_appeared = await page.evaluate('''
                    () => new Promise(resolve => {
                        window.alert = () => resolve(true);
                        setTimeout(() => resolve(false), 1000);
                    })
                ''')
                
                if dialog_appeared:
                    self.vulnerabilities.append(f"DOM-based XSS found in {url} using {handler}")
                    break
                

        except Exception as e:
            print(f"Error checking DOM XSS for {url}: {e}")
        finally:
            await page.close()




    async def check_stored_xss(self,url,content):
        payloads = self.payload_generator.generate_payloads()
        submitted_payloads = []

        # Submit payloads to forms
        soup = BeautifulSoup(content,"html.parser")
        forms = soup.find_all("form")
        for form in forms:
           submitted = await self.submit_stored_xss(url,form,payloads)
           submitted_payloads.extend(submitted)

        # Wait a bit for payloads to be stored
        await asyncio.sleep(5)
        # Now check for the submitted payloads
        await self.check_for_stored_payloads(submitted_payloads)


    async def submit_stored_xss(self,url,form,payloads):
        action = urljoin(url, form.get('action',''))
        method = form.get('method','get').lower()
        submitted = []

        for payload in payloads:
            data = {input.get('name'): payload for input in form.find_all('input') if input.get('name')}

            try:
                if method == "post":
                    await self.session.post(action , data=data)
                else:
                    await self.session.get(action, params= data)
                submitted.append((action,payload))
            except Exception as e:
                print(f"Error submitting to {action} : {e}")
        return submitted
    
    async def check_for_stored_payloads(self,submitted_payloads):
        for url in self.visited_urls:
            try:
                async with self.session.get(url) as response:
                    content = await response.text()
                    for submission_url, payload in submitted_payloads:
                        if payload in content and submission_url != url:
                            self.vulnerabilities.append(f"Stored XSS found: payload submitted to {submission_url} appeard in {url}")
            except Exception as e:
                print(f"Error checking {url} for stored XSS: {e}" )                

    async def check_reflected_xss(self,url,content):
        payloads =self.payload_generator.generate_payloads()
        # check URl parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        for param, values in params.items():
            for payload in payloads:
                test_url = url.replace(f"{param}={values[0]}",f"{param}={payload}")
                async with self.session.get(test_url) as response:
                    response_text = await response.text()
                    if payload in response_text:
                        self.vulnerabilities.append(f"Reflected XSS found in URL parameter {param} at {url}")
        # check form inputs
        soup = BeautifulSoup(content,"html.parser")
        forms = soup.find_all("form")
        for form in forms:
            await self.check_form_xss(url,form,payloads)
        
    async def check_form_xss(self,url,form,payloads):
        action = urljoin(url,form.get("action",''))
        method = form.get('method','get').lower()
        for payload in payloads:
            data = {input.get('name'): payload for input in form.find_all('input') if input.get('name')}
            if method == 'post':
                async with self.session.post(action,data=data) as response:
                    response_text = await response.text()
            else:
                async with self.session.get(action, params = data)as response:
                    response_text = await response.text()
        if payload in response_text:
            self.vulnerabilities.append(f"Reflected XSS ound in form at {url}")
            return





class PayloadGenerator:
    def generate_payloads(self):
        return [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<a href=\"javascript:alert('XSS')\">Click me</a>"
        ]

# class PayloadGenerator:
#     def __init__(self):
#         self.base_payloads = [
#             "<script>alert('XSS')</script>",
#             "<img src=x onerror=alert('XSS')>",
#             "<svg onload=alert('XSS')>",
#             "javascript:alert('XSS')",
#             "<iframe src=\"javascript:alert('XSS')\"></iframe>",
#             "<a href=\"javascript:alert('XSS')\">Click me</a>",
#             "<div onmouseover=\"alert('XSS')\">Hover over me</div>",
#             "<input type=\"text\" value=\"\" onfocus=\"alert('XSS')\" autofocus>",
#             "<body onload=alert('XSS')>",
#             "<object data=\"javascript:alert('XSS')\">",
#             "<embed src=\"javascript:alert('XSS')\">",
#             "<marquee onstart=alert('XSS')>",
#             "<isindex type=image src=1 onerror=alert('XSS')>",
#             "<table background=\"javascript:alert('XSS')\">",
#             "<svg/onload=alert('XSS')>"
#         ]



# def mutate_single_payload(self, payload):
#     mutations = [
#         self.change_alert_function,
#         self.add_encoding,
#         self.change_quotes,
#         self.add_obfuscation,
#         self.change_tag,
#         self.split_payload
#     ]
#     return random.choice(mutations)(payload)

# def change_alert_function(self, payload):
#     alert_alternatives = ['prompt', 'confirm', 'console.log', 'eval']
#     return payload.replace('alert', random.choice(alert_alternatives))

# def add_encoding(self, payload):
#     return html.escape(payload)

# def change_quotes(self, payload):
#     return payload.replace("'", "\"") if "'" in payload else payload.replace("\"", "'")

# def add_obfuscation(self, payload):
#     obfuscated = ''.join([f'&#x{ord(c):x};' for c in payload])
#     return f"<script>eval('{obfuscated}')</script>"

# def change_tag(self, payload):
#     if payload.startswith('<script>'):
#         new_tags = ['<div>', '<span>', '<p>']
#         new_tag = random.choice(new_tags)
#         return payload.replace('<script>', f"{new_tag}<script>").replace('</script>', f"</script>{new_tag.replace('<', '</>')}")
#     return payload

# def split_payload(self, payload):
#     if 'alert' in payload:
#         parts = payload.split('alert')
#         return f"{parts[0]}al' + 'ert{parts[1]}"
#     return payload


# def combine_payloads(self, payload1, payload2):
#     return f"{payload1}{payload2}"

# def generate_payloads(self):
#     mutated_payloads = self.mutate_payloads(self.base_payloads)
#     combined_payloads = [self.combine_payloads(p1, p2) 
#                          for p1 in self.base_payloads 
#                          for p2 in mutated_payloads]
#     return self.base_payloads + mutated_payloads + combined_payloads


# def generate_context_aware_payloads(self, context):
#     if context == 'attribute':
#         return [f'" onmouseover="alert(\'XSS\')" "', 
#                 f"' onfocus='alert(\"XSS\")' '"]
#     elif context == 'script':
#         return [f"'-alert('XSS')-'", 
#                 f"\"-alert('XSS')-\""]
#     elif context == 'url':
#         return [f"javascript:alert('XSS')", 
#                 f"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="]
#     else:
#         return self.generate_payloads()

# def analyze_and_generate(self, target_content):
#     if '<script>' in target_content:
#         return self.generate_context_aware_payloads('script')
#     elif 'href=' in target_content or 'src=' in target_content:
#         return self.generate_context_aware_payloads('url')
#     elif '=' in target_content:
#         return self.generate_context_aware_payloads('attribute')
#     else:
#         return self.generate_payloads()