from flask import Flask, jsonify,request
from flask_cors import CORS
from scanner import AdvancedScanner

app = Flask(__name__)
CORS(app)

links_to_ignore = [""]



@app.route('/analyse', methods=['POST'])
def analyse():
    data = request.json
    url = data.get('url','')
    # result = f"Analysed url:{url}"
    result = analyze_security(url)
    return jsonify({"result":result})


def analyze_security(url):
    vuln_scanner = AdvancedScanner(url)
    vuln_scanner.crawl()
    vulnerabilities = vuln_scanner.run_scanner()
    
    return {
        "url": url,
        "vulnerabilities": vulnerabilities,
        "scanned_pages": list(vuln_scanner.target_links)
    }

if __name__ == "__main__":
    app.run(port=5000)


    