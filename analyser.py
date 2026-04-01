import email
from email import policy
import re

def parse_eml(file_stream):
    """
    Parses a raw .eml file stream and extracts headers and URLs.
    """
    # Parse the email from the file stream (Flask streams are binary)
    file_bytes = file_stream.read()
    msg = email.message_from_bytes(file_bytes, policy=policy.default)
    
    # 1. Extract Headers
    headers_to_extract = ['From', 'To', 'Subject', 'Date', 'Message-ID', 'Authentication-Results', 'Return-Path']
    extracted_headers = {}
    
    for header in headers_to_extract:
        # Use get to avoid KeyError ifheader is missing
        extracted_headers[header] = msg.get(header, 'Not Found')
        
    # Extract Received headers (can be multiple)
    received_headers = msg.get_all('Received')
    if received_headers:
        extracted_headers['Received'] = [h.strip() for h in received_headers]
    else:
        extracted_headers['Received'] = []

    # 2. Extract Body and URLs
    body = ""
    urls = []
    
    # regex to find http/https URLs
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*')
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            filename = part.get_filename()
            if filename:
                if 'Attachments' not in extracted_headers:
                    extracted_headers['Attachments'] = []
                extracted_headers['Attachments'].append(filename)
                continue # Skip parsing the body of attachments
            
            # Skip non-text parts
            if "attachment" not in content_disposition:
                if content_type == "text/plain" or content_type == "text/html":
                    try:
                        part_body = part.get_content()
                        if isinstance(part_body, bytes):
                            part_body = part_body.decode('utf-8', errors='ignore')
                        body += part_body + "\n"
                        # Find URLs in this part
                        urls.extend(url_pattern.findall(part_body))
                    except Exception as e:
                        pass
    else:
        # Not multipart, just a single payload
        try:
            body = msg.get_content()
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='ignore')
            urls.extend(url_pattern.findall(body))
        except Exception as e:
            pass

    # Deduplicate URLs
    urls = list(set(urls))
    
    return {
        'headers': extracted_headers,
        'body': body[:1200] + ('...' if len(body) > 1200 else ''), # Truncated preview
        'urls': urls
    }

if __name__ == "__main__":
    import argparse
    import json
    import io
    import os
    from dotenv import load_dotenv
    from virustotal import scan_urls
    from scoring import calculate_risk_score
    from datetime import datetime
    
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Phishing Email Analyser")
    parser.add_argument("--email", required=True, help="Path to the raw .eml file")
    parser.add_argument("--apikey", default=os.environ.get("VT_API_KEY", "dummy"), help="VirusTotal API Key")
    parser.add_argument("--no-vt", action="store_true", help="Skip VirusTotal scanning")
    parser.add_argument("--json", action="store_true", help="Output report in JSON format")
    args = parser.parse_args()
    
    with open(args.email, "rb") as f:
        file_bytes = f.read()
        parsed = parse_eml(io.BytesIO(file_bytes))
        
    urls = parsed.get("urls", [])
    if args.no_vt or args.apikey == "dummy":
        vt_results = {url: {"status": "VT Skipped (--no-vt or dummy key)"} for url in urls}
    else:
        vt_results = scan_urls(urls, args.apikey)
        
    risk = calculate_risk_score(parsed, vt_results)
    
    if args.json:
        print(json.dumps({
            "headers": parsed["headers"],
            "urls": urls,
            "vt_results": vt_results,
            "risk_assessment": risk
        }, indent=2))
    else:
        print("════════════════════════════════════════════════════════════════")
        print("  PHISHING EMAIL ANALYSER — THREAT REPORT")
        print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("════════════════════════════════════════════════════════════════\n")
        print(f"  File   : {args.email}")
        print(f"  From   : {parsed['headers'].get('From', 'N/A')}")
        print(f"  Subject: {parsed['headers'].get('Subject', 'N/A')}\n")
        print("────────────────────────────────────────────────────────────────")
        print(f"  RISK SCORE: {risk['score']}/100")
        verdict = f"{risk['risk_level']} RISK — likely phishing" if risk['score'] >= 60 else f"{risk['risk_level']} RISK"
        print(f"  VERDICT   : {verdict}")
        bar_len = int((risk['score'] / 100) * 20)
        print(f"  {'█'*bar_len}{'▒'*(20-bar_len)} {risk['risk_level']} RISK\n")
        print("────────────────────────────────────────────────────────────────")
        print(f"  HEADER ANALYSIS  ({len(risk['findings'])} findings)")
        for finding in risk['findings']:
            print(f"  {finding}")
        print("\n────────────────────────────────────────────────────────────────")
        print(f"  URL ANALYSIS  ({len(urls)} unique URLs found)")
        if not urls:
            print("  No URLs detected.")
        for url, stats in vt_results.items():
            if "error" in stats or "status" in stats:
                print(f"  - {url} ({stats.get('error', stats.get('status'))})")
            else:
                mark = "✗ MALICIOUS" if stats.get("malicious", 0) > 0 else "✓ CLEAN"
                print(f"  {mark}")
                print(f"    URL    : {url}")
                print(f"    Engines: {stats.get('malicious',0)} malicious, {stats.get('suspicious',0)} suspicious, {stats.get('harmless',0)} harmless")

