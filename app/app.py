from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return jsonify({'message':'hello world'})

@app.route('/sum', methods=['POST'])
def sum():
    in_data = request.get_json()
    if in_data.get('a'):
        return jsonify({'message':'dados recebidos'})
    return jsonify({'message':'dados faltantes'})

app.run(debug=True)