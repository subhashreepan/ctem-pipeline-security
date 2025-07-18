from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

@app.route('/')
def dashboard():
    json_path = os.path.join(os.path.dirname(__file__), '../dashboard/data.json')
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    return render_template('dashboard.html', data=data)

if __name__ == '__main__':
    app.run(debug=True)
