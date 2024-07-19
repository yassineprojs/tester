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
    # result = f"Analysed url:{url}"
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
        
        return {
            "url": url,
            "vulnerabilities": vuln_scanner.vulnerabilities,
            "scanned_pages": list(vuln_scanner.visited_urls)
        }
   
    except Exception as e:
        logging.error(f"Error in analyze_security: {str(e)}")
        raise

if __name__ == "__main__":
    app.run(port=5000,debug=True)


    