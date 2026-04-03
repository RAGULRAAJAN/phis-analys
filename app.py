import os
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from analyser import parse_eml
from virustotal import scan_urls
from scoring import calculate_risk_score
from dotenv import load_dotenv

try:
    from yara_engine import scan_with_yara
except ImportError:
    scan_with_yara = lambda x: {"error": "YARA not configured locally"}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans_alchemy.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    sender = db.Column(db.String(200))
    subject = db.Column(db.String(200))
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(50))
    attack_vectors = db.Column(db.String(500))
    llm_explanation = db.Column(db.Text)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)

load_dotenv()

with app.app_context():
    db.create_all()
    # Migrate old sqlite3 data
    import sqlite3
    if os.path.exists('scans.db'):
        try:
            with sqlite3.connect('scans.db') as conn:
                cur = conn.cursor()
                cur.execute('SELECT filename, sender, subject, risk_score, risk_level, scan_date FROM scan_history')
                rows = cur.fetchall()
                for r in rows:
                    if not ScanHistory.query.filter_by(filename=r[0], scan_date=datetime.strptime(r[5], '%Y-%m-%d %H:%M:%S') if isinstance(r[5], str) else r[5]).first():
                        db.session.add(ScanHistory(
                            filename=r[0], sender=r[1], subject=r[2], risk_score=r[3], risk_level=r[4],
                            attack_vectors='', llm_explanation='',
                            scan_date=datetime.strptime(r[5], '%Y-%m-%d %H:%M:%S') if isinstance(r[5], str) else r[5]
                        ))
                db.session.commit()
        except Exception:
            pass

VT_API_KEY = os.environ.get("VT_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

try:
    import openai
    if OPENAI_API_KEY:
        openai.api_key = OPENAI_API_KEY
except ImportError:
    openai = None

def get_llm_explanation(parsed, risk):
    if not openai or not OPENAI_API_KEY:
        # Free Local Heuristic Fallback
        subject = parsed.get('headers', {}).get('Subject', 'Unknown')
        sender = parsed.get('headers', {}).get('From', 'Unknown User')
        findings_count = len(risk.get('findings', []))
        
        summary = f"Analysis of '{subject}' from sender '{sender}': "
        if risk.get('score', 0) >= 70:
            summary += "CRITICAL ALERT. This email exhibits extreme indicators of compromise. "
        elif risk.get('score', 0) >= 40:
            summary += "WARNING. Several suspicious elements have been flagged. "
        else:
            summary += "This communication currently appears benign. "
            
        if findings_count > 0:
            summary += f"The threat engine isolated {findings_count} active threat vectors across the headers, URLs, and binary attachments. Do not interact with links."
        else:
            summary += "No immediate structural or metadata threats detected."
        return summary
    try:
        prompt = f"Explain this phishing attempt in 3 sentences to a layman. Subject: {parsed.get('headers',{}).get('Subject')}. From: {parsed.get('headers',{}).get('From')}. Body context: {str(parsed.get('body', ''))[:1000]}. Findings: {json.dumps(risk.get('findings', []))}"
        if openai.__version__.startswith('0.'):
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "system", "content": "You are a cybersecurity expert."}, {"role": "user", "content": prompt}]
            )
            return response['choices'][0]['message']['content'].strip()
        else:
            client = openai.OpenAI(api_key=OPENAI_API_KEY)
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "system", "content": "You are a cybersecurity expert."}, {"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content.strip()
    except Exception as e:
        return f"LLM Error: {str(e)}"

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
            file_bytes = file.read()
            from io import BytesIO
            parsed_data = parse_eml(BytesIO(file_bytes))
            
            # YARA
            yara_results = scan_with_yara(file_bytes)
            
            # VT
            urls_to_scan = parsed_data.get('urls', [])
            vt_results = scan_urls(urls_to_scan, VT_API_KEY)
            
            # Risk
            risk_assessment = calculate_risk_score(parsed_data, vt_results)
            
            if yara_results and yara_results.get('matches'):
                yara_msg = f"[ HIGH   ] {len(yara_results['matches'])} YARA Matches detected"
                if yara_msg not in risk_assessment['findings']:
                    risk_assessment['findings'].append(yara_msg)
                risk_assessment['score'] = min(100, risk_assessment['score'] + 20)
                risk_assessment['risk_level'] = 'HIGH' if risk_assessment['score'] >= 70 else ('MEDIUM' if risk_assessment['score'] >= 40 else 'LOW')

            # LLM
            llm_text = get_llm_explanation(parsed_data, risk_assessment)
            
            # Vectors
            vectors_str = ' | '.join([f.replace('[ HIGH   ] ', '').replace('[ MEDIUM ] ', '').replace('[ LOW    ] ', '') for f in risk_assessment['findings']])
            
            # Save Alchemy DB
            new_scan = ScanHistory(
                filename=file.filename,
                sender=str(parsed_data.get('headers', {}).get('From', 'Unknown')),
                subject=str(parsed_data.get('headers', {}).get('Subject', 'No Subject')),
                risk_score=risk_assessment['score'],
                risk_level=risk_assessment['risk_level'],
                attack_vectors=vectors_str,
                llm_explanation=llm_text
            )
            db.session.add(new_scan)
            db.session.commit()
            
            return jsonify({
                "status": "success",
                "id": new_scan.id,
                "headers": parsed_data['headers'],
                "urls_found": len(urls_to_scan),
                "vt_results": vt_results,
                "risk_assessment": risk_assessment,
                "yara_findings": yara_results.get('matches', []),
                "llm_explanation": llm_text,
                "body": parsed_data.get("body", ""),
                "spoof_findings": parsed_data.get("spoof_findings", []),
                "typo_findings": parsed_data.get("typo_findings", []),
                "social_findings": parsed_data.get("social_findings", []),
                "social_score": parsed_data.get("social_score", 0),
                "relay_findings": parsed_data.get("relay_findings", []),
                "attach_findings": parsed_data.get("attach_findings", []),
            })
        except Exception as e:
            import traceback
            return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500
    return jsonify({'error': 'Invalid file format. Please upload a .eml file.'}), 400

@app.route('/dashboard')
def dashboard():
    scans = ScanHistory.query.order_by(ScanHistory.scan_date.desc()).all()
    
    total_scans = len(scans)
    avg_score = int(sum(s.risk_score for s in scans) / total_scans) if total_scans > 0 else 0
    high_risk_count = sum(1 for s in scans if s.risk_level == 'HIGH')
    
    vectors_count = {}
    for s in scans:
        if s.attack_vectors:
            for v in s.attack_vectors.split(', '):
                vectors_count[v] = vectors_count.get(v, 0) + 1
    
    # Sort vectors by count (descending)
    common_vectors = sorted(vectors_count.items(), key=lambda x: x[1], reverse=True)[:3]
    
    return render_template('dashboard.html', scans=scans, stats={
        "total": total_scans,
        "avg_score": avg_score,
        "high_risk": high_risk_count,
        "common_vectors": common_vectors
    })

@app.route('/export_report/<int:scan_id>')
def export_report(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    html = render_template('report.html', scan=scan)
    try:
        response = make_response(html)
        response.headers['Content-Type'] = 'text/html'
        response.headers['Content-Disposition'] = f'attachment; filename=threat_report_{scan_id}.html'
        return response
    except Exception as e:
        return f"Report generating failed. Error: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True, port=5000)
