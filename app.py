import os
from flask import Flask, render_template, request, jsonify
from analyzer import parse_eml
from virustotal import scan_urls
from scoring import calculate_risk_score

app = Flask(__name__)

# To test securely, set your API key as an environment variable before running
VT_API_KEY = os.environ.get("VT_API_KEY", "") 

@app.route('/')
def index():
    return render_template('index.html')

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
            
            return jsonify({
                "status": "success",
                "headers": parsed_data['headers'],
                "urls_found": len(urls_to_scan),
                "vt_results": vt_results,
                "risk_assessment": risk_assessment
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
            
    return jsonify({'error': 'Invalid file format. Please upload a .eml file.'}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
