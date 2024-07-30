import asyncio
from quart import Quart, request, jsonify
from quart_cors import cors
from scanner import AdvancedScanner
import logging

app = Quart(__name__)
app = cors(app)
logging.basicConfig(level=logging.DEBUG)


@app.route('/analyse', methods=['POST'])
async def analyse():
    data = await request.get_json()
    url = data.get('url','')
    try:
        result = await analyze_security(url)
        return jsonify({"result": result})
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return jsonify({"error": "An error occurred during analysis", "details": str(e)}), 500



async def analyze_security(url):
    try:
        vuln_scanner = AdvancedScanner(url)
        await vuln_scanner.crawl()
        
        result = await vuln_scanner.get_results()
        result["url"] = url
        return result

   
    except Exception as e:
        logging.error(f"Error in analyze_security: {str(e)}")
        raise

if __name__ == "__main__":
    app.run(port=5000,debug=True)


    # async def process_url(self):
    #     while True:
    #         url, depth = await self.urls_to_visit.get()
    #         if url not in self.visited_urls and len(self.visited_urls) < self.max_urls:
    #             self.visited_urls.add(url)
    #             print(f"Scanning: {url}")
    #             try:
    #                 async with self.session.get(url, timeout=10) as response:
    #                     content = await response.text()
    #                     # cookies = response.cookies

    #                     xss_results = await self.xss_scanner.analyze(url, content)
    #                     leakage_results = await self.leakage_detector.analyze(url)
    #                     print(f"Leakage results for {url}: {leakage_results}")
    #                     sql_results = await self.sql_injection_checker.analyze(url)
    #                     ssl_tls_results = await self.ssl_tls_analyzer.analyze(url)

    #                     # cookie_results = await self.cookie_analyser.analyze(url, cookies)

    #                     subsite_score =(
    #                         # xss_results.get('total_score',0) 
    #                         leakage_results.get('score',0) 
    #                         # sql_results.get('score',0)+
    #                         # ssl_tls_results.get('score', 0)
    #                         )
    #                     self.total_score += subsite_score

    #                     self.scan_results.append({
    #                         "url": url,
    #                        
    #                         "subsite_score":subsite_score
    #                     })
    #                     if depth < self.max_depth:
    #                         await self.extract_links(url, content, depth + 1)
    #             except Exception as e:
    #                 print(f"Error processing {url}: {e}")
    #         self.urls_to_visit.task_done()