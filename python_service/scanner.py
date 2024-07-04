import asyncio #For asynchronous programming
import aiohttp #For making asynchronous HTTP requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse #For URL manipulation
import re
from xss import XSSscanner

class AdvancedScanner:
    def __init__(self, url, max_depth=3, max_urls=100, concurrency=10):
        self.start_url = url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.concurrency = concurrency
        self.visited_urls = set()
        self.urls_to_visit = asyncio.Queue()
        self.session = None
        self.vulnerabilities = []
        self.xss_scanner = XSSscanner(self.session,self.visited_urls)

    async def create_session(self):
        self.session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))

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
                        await self.check_vulnerabilities(url, content)
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

    async def check_vulnerabilities(self, url, content):
        self.xss_scanner.session = self.session
        self.xss_scanner.visited_urls = self.visited_urls
        await asyncio.gather(
            self.xss_scanner.scan(url,content),
            self.vulnerabilities.extend(self.xss_scanner.vulnerabilities)
            # self.check_sql_injection(url)
            # self.check_open_redirect(url),
            # self.check_ssl(url),
            # self.check_headers(url),
)


  















































# import requests
# import re
# from urllib.parse import urlparse,urljoin
# from bs4 import BeautifulSoup

# class Scanner:
#     def __init__(self,url,ignore_links):
#         self.session = requests.session()
#         self.target_url = url
#         self.target_links = set()
#         self.links_to_ignore = set(ignore_links)

#     # crawler
#     def extract_links_from(self,url):
#         try:
#             response = self.session.get(url)
#             response.raise_for_status()
#             return re.findall('(?:href=")(.*?)"', response.text)
#         except requests.RequestException as e:
#             print(f"Error fetching {url}: {e}")
#             return []
        
#     def crawl(self,url=None):
#         url = url or self.target_url
#         href_links = self.extract_links_from(url)
#         for link in href_links:
#             link = urljoin(url, link)
#             parsed_link = urlparse(link)
#             link = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
#             if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
#                 self.target_links.add(link)
#                 print(link)
#                 self.crawl(link)

            
#     def extract_forms(self, url):
#         try:
#             response = self.session.get(url)
#             response.raise_for_status()
#             soup = BeautifulSoup(response.text, 'html.parser')
#             return soup.find_all("form")
#         except requests.RequestException as e:
#             print(f"Error fetching {url}: {e}")
#             return []
    
#     def submit_form(self, form, value, url):
#         action = form.get("action")
#         post_url = urljoin(url, action)
#         method = form.get("method", "get").lower()
#         inputs_list = form.find_all("input")
#         data = {}

#         for input_field in inputs_list:
#             name = input_field.get("name")
#             input_type = input_field.get("type", "text")
#             if name:
#                 if input_type == "text":
#                     data[name] = value
#                 else:
#                     data[name] = input_field.get("value", "")

#         try:
#             if method == "post":
#                 return self.session.post(post_url, data=data)
#             return self.session.get(post_url, params=data)
#         except requests.RequestException as e:
#             print(f"Error submitting form to {post_url}: {e}")
#             return None
    
#     def run_scanner(self):
#         vulnerabilities = []
#         for link in self.target_links:
#             forms = self.extract_forms(link)
#             for form in forms:
#                 print(f"Testing form in {link}")
#                 is_vulnerable_to_xss = self.test_xss_in_form(form, link)
#                 if is_vulnerable_to_xss:
#                     vulnerabilities.append(f"XSS vulnerability in form at {link}")

#             if "=" in link:
#                 print(f"Testing {link}")
#                 is_vulnerable_to_xss = self.test_xss_in_link(link)
#                 if is_vulnerable_to_xss:
#                     vulnerabilities.append(f"XSS vulnerability in link: {link}")

#         return vulnerabilities

#     def test_xss_in_link(self, url):
#         xss_test_script = "<sCript>alert('test')</scriPt>"
#         url = url.replace("=", "=" + xss_test_script)
#         try:
#             response = self.session.get(url)
#             return xss_test_script.lower() in response.text.lower()
#         except requests.RequestException:
#             return False

#     def test_xss_in_form(self, form, url):
#         xss_test_script = "<script>alert('test')</script>"
#         response = self.submit_form(form, xss_test_script, url)
#         return response and xss_test_script.lower() in response.text.lower()
        
