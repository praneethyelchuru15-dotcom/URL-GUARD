import os
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_compress import Compress
from flask_sqlalchemy import SQLAlchemy
import main
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)
Compress(app)

# Database Configuration
# Uses Render's DATABASE_URL if available, otherwise falls back to local SQLite
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Model
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    risk_score = db.Column(db.Integer)
    timestamp = db.Column(db.String)
    details_json = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "risk_score": self.risk_score,
            "timestamp": self.timestamp
        }

# Initialize DB
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/history')
def history_page():
    return render_template('history.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    try:
        report = main.scan_url(url)
        
        # Save to DB (ORM)
        new_scan = ScanResult(
            url=report['url'],
            risk_score=report['total_risk_score'],
            timestamp=report.get('timestamp', datetime.now().isoformat()),
            details_json=json.dumps(report)
        )
        db.session.add(new_scan)
        db.session.commit()
            
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/history')
def get_history():
    try:
        # Fetch last 50 scans (ORM)
        scans = ScanResult.query.order_by(ScanResult.id.desc()).limit(50).all()
        return jsonify([scan.to_dict() for scan in scans])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
