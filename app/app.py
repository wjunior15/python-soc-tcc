from flask import Flask, jsonify, request
from flask_cors import CORS
import os

app_host = str(os.getenv("APP_HOST"))
app_port = int(os.getenv("APP_PORT"))

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


app.run(host=app_host, port=app_port, debug=True)
