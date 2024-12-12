from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import redis

app_host = str(os.getenv("APP_HOST"))
app_port = int(os.getenv("APP_PORT"))
redis_host = str(os.getenv("REDIS_HOST"))
redis_port = int(os.getenv("REDIS_PORT"))

APP_USER = 'admin'
APP_PASSWORD = 'senha123'

app = Flask(__name__)
CORS(app)

redis_client = redis.StrictRedis(host=redis_host, port=redis_port, decode_responses=True)
redis_client.set('value',0)

@app.route('/', methods=['GET'])
def index():
    return jsonify({'message':'hello world'})

@app.route('/sum', methods=['POST'])
def sum():
    in_data = request.get_json()
    if in_data.get('a'):
        #Realiza busca no cache e soma valores - Armazena resultado no cache
        value_b = int(redis_client.get('value'))
        total_value = int(in_data.get('a'))+value_b
        redis_client.set('value', total_value)
        return jsonify({'message':'operação realizada',
                        'valor total':total_value})
        
    return jsonify({'message':'dados faltantes'})

@app.route('/login', methods=['POST'])
def login():
    # Get username and password from the request
    username = request.form.get('username')
    password = request.form.get('password')

    # Check if the username and password are correct
    if username == APP_USER and password == APP_PASSWORD:
        return jsonify({"status": "success", "message": "Login successful!"}), 200
    else:
        return jsonify({"status": "failure", "message": "Invalid credentials."}), 401

app.run(host=app_host, port=app_port, debug=True)
