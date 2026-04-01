import os
import sqlite3
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from analyzer import parse_eml
from virustotal import scan_urls
from scoring import calculate_risk_score

app = Flask(__name__)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('scans.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  filename TEXT,
                  score INTEGER,
                  risk_level TEXT,
                  timestamp DATETIME,
                  details TEXT)''')
    conn.commit()
    conn.close()

init_db()

# To test securely, set your API key as an environment variable before running
VT_API_KEY = os.environ.get("VT_API_KEY", "") 

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/history')
def get_history():
    conn = sqlite3.connect('scans.db')
    c = conn.cursor()
    c.execute("SELECT id, filename, score, risk_level, timestamp FROM scans ORDER BY timestamp DESC LIMIT 5")
    rows = c.fetchall()
    conn.close()
    history = [{"id": r[0], "filename": r[1], "score": r[2], "risk_level": r[3], "timestamp": r[4]} for r in rows]
    return jsonify(history)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and file.filename.endswith('.eml'):
        try:
            # 1. Parse Email
            parsed_data = parse_eml(file.stream)
            
            # 2. Scan URLs via VT
            urls_to_scan = parsed_data.get('urls', [])
            # VT Scanning could take long (15s per URL). For a real production app with UI, 
            # this would be async/websockets. For this Flask showcase app, we just block.
            vt_results = scan_urls(urls_to_scan, VT_API_KEY)
            
            # 3. Calculate Risk
            risk_assessment = calculate_risk_score(parsed_data, vt_results)
            
            # 4. Save to Database
            try:
                conn = sqlite3.connect('scans.db')
                c = conn.cursor()
                c.execute("INSERT INTO scans (filename, score, risk_level, timestamp, details) VALUES (?, ?, ?, ?, ?)",
                          (file.filename, risk_assessment['score'], risk_assessment['risk_level'], datetime.now(), json.dumps(risk_assessment)))
                conn.commit()
                conn.close()
            except Exception as db_err:
                print("DB Error:", db_err)
            
            return jsonify({
                "status": "success",
                "headers": parsed_data['headers'],
                "urls_found": len(urls_to_scan),
                "vt_results": vt_results,
                "risk_assessment": risk_assessment,
                "body": parsed_data.get("body", "") # Now body preview is sent to frontend
            })
        except Exception as e:
            import traceback
            return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500
            
    return jsonify({'error': 'Invalid file format. Please upload a .eml file.'}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
