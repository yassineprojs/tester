class AdvancedScanner:
    def __init__(self, url, max_depth=3, max_urls=100, concurrency=10):
        self.start_url = url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.concurrency = concurrency
        self.visited_urls = set()
        self.urls_to_visit = asyncio.Queue()
        self.session = None
        self.xss_scanner = XSSSecurityAnalyzer(self.session, self.visited_urls)
        self.cookie_analyzer = CookieSecurityAnalyzer(url)
        self.vulnerabilities = []

    # ... (other methods remain the same)

    async def check_vulnerabilities(self, url, content):
        self.xss_scanner.session = self.session
        self.xss_scanner.visited_urls = self.visited_urls
        
        # Perform XSS analysis
        await self.xss_scanner.analyze(url, content)
        self.vulnerabilities.extend(self.xss_scanner.vulnerabilities)
        
        # Perform cookie analysis
        cookie_results = self.cookie_analyzer.analyze()
        if 'error' in cookie_results:
            self.vulnerabilities.append({
                'type': 'Cookie Analysis Error',
                'url': url,
                'details': cookie_results['error']
            })
        else:
            for cookie in cookie_results.get('cookies', []):
                if 'warnings' in cookie:
                    for warning in cookie['warnings']:
                        self.vulnerabilities.append({
                            'type': 'Cookie Vulnerability',
                            'url': url,
                            'details': f"Cookie '{cookie['name']}': {warning}"
                        })
            
            security_score = cookie_results.get('security_score', 0)
            if security_score < 5:
                self.vulnerabilities.append({
                    'type': 'Low Cookie Security Score',
                    'url': url,
                    'details': f"Cookie security score: {security_score}/10"
                })

    async def crawl(self):
        await self.create_session()
        await self.urls_to_visit.put((self.start_url, 0))

        tasks = [asyncio.create_task(self.process_url()) for _ in range(self.concurrency)]
        await self.urls_to_visit.join()

        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Perform cookie analysis for the start URL
        cookie_results = self.cookie_analyzer.analyze()
        self.process_cookie_results(self.start_url, cookie_results)
        
        await self.close_session()

    def process_cookie_results(self, url, cookie_results):
        if 'error' in cookie_results:
            self.vulnerabilities.append({
                'type': 'Cookie Analysis Error',
                'url': url,
                'details': cookie_results['error']
            })
        else:
            for cookie in cookie_results.get('cookies', []):
                if 'warnings' in cookie:
                    for warning in cookie['warnings']:
                        self.vulnerabilities.append({
                            'type': 'Cookie Vulnerability',
                            'url': url,
                            'details': f"Cookie '{cookie['name']}': {warning}"
                        })
            
            security_score = cookie_results.get('security_score', 0)
            if security_score < 5:
                self.vulnerabilities.append({
                    'type': 'Low Cookie Security Score',
                    'url': url,
                    'details': f"Cookie security score: {security_score}/10"
                })