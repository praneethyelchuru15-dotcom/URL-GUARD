from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import main  # Import our existing scanner logic

app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    try:
        # Re-use our existing scan logic!
        report = main.scan_url(url)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
