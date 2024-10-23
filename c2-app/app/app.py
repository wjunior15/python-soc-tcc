from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def index():
    return jsonify({'message':'hello world'})

@app.route('/sum', methods=['POST'])
def sum():
    in_data = request.get_json()
    if in_data.get('a'):
        return jsonify({'message':'dados recebidos'})
    return jsonify({'message':'dados faltantes'})

app.run(host='0.0.0.0', port=8080, debug=True)