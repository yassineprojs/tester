from flask import Flask, jsonify,request
from flask_cors import CORS
from bs4 import BeautifulSoup
import scanner

app = Flask(__name__)
CORS(app)



@app.route('/analyse', methods=['POST'])
def analyse():
    data = request.json
    url = data.get('url','')
    # result = f"Analysed url:{url}"
    result = analyze_security(url)
    return jsonify({"result":result})


def analyze_security(url):
    vuln_scanner  = scanner.Scanner(url)
    vuln_scanner.crawl()
#     response = request(url)
#     parsed_html = BeautifulSoup(response.content)
    # forms_list = parsed_html.findAll("form")
    # for form in forms_list:
    #     post_url = urljoin(url,action)
    #     action = form.get("action")
    #     method = form.get("method")

    #     inputs_list=form.findAll("input")
    #     for input in inputs_list:
    #         input_name=input.get("name")
    #         input_type = input.get("type")
    #         if  input_type == "text":
    #             input_value = "test"
        

if __name__ == "__main__":
    app.run(port=5000)


    