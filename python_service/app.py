from flask import Flask, jsonify,request

app = Flask(__name__)

@app.route('/analyse', methods=['POST'])
def analyse():
    data = request.json
    url = data.get('url','')

    result = f"Analysed url:{url}"

    return jsonify({"result":result})



if __name__ == "__main__":
    app.run(port=5000)


    