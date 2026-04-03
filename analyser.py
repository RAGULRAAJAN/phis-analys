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
        extracted_headers[header] = msg.get(header, 'Not Found')

    # Extract Received headers (can be multiple)
    received_headers = msg.get_all('Received')
    if received_headers:
        extracted_headers['Received'] = [h.strip() for h in received_headers]
    else:
        extracted_headers['Received'] = []

    # 2. Extract Body and URLs (with HTML deobfuscation)
    body = ""
    urls = []
    attachments_data = []  # List of (filename, raw_bytes)

    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<"]*')

    def _decode_html_entities(text):
        """Decode common HTML entity obfuscation (e.g., &#x68; -> h)."""
        def replace_hex(m):
            try:
                return chr(int(m.group(1), 16))
            except (ValueError, OverflowError):
                return m.group(0)
        def replace_dec(m):
            try:
                return chr(int(m.group(1)))
            except (ValueError, OverflowError):
                return m.group(0)
        text = re.sub(r'&#x([0-9a-fA-F]+);', replace_hex, text)
        text = re.sub(r'&#(\d+);', replace_dec, text)
        return text

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            filename = part.get_filename()
            if filename:
                if 'Attachments' not in extracted_headers:
                    extracted_headers['Attachments'] = []
                extracted_headers['Attachments'].append(filename)
                try:
                    raw = part.get_payload(decode=True)
                    if raw:
                        attachments_data.append((filename, raw))
                except Exception:
                    pass
                continue

            if "attachment" not in content_disposition:
                if content_type == "text/plain" or content_type == "text/html":
                    try:
                        part_body = part.get_content()
                        if isinstance(part_body, bytes):
                            part_body = part_body.decode('utf-8', errors='ignore')
                        body += part_body + "\n"
                    except Exception as e:
                        pass
    else:
        try:
            body = msg.get_content()
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='ignore')
        except Exception as e:
            pass

    body_decoded = _decode_html_entities(body)
    urls.extend(url_pattern.findall(body))
    urls.extend(url_pattern.findall(body_decoded))
    urls = list(set(urls))

    # 3. Display name spoofing & typosquatting checks
    from spoofing import (
        check_display_name_spoofing,
        check_typosquatting,
        parse_email_address,
    )
    spoof_findings = check_display_name_spoofing(extracted_headers)
    extracted_headers.setdefault(
        "Spoofing Findings",
        [f.strip('[').strip(' MEDIUM ] HIGH   ] LOW    ]') for f in spoof_findings],
    )

    domains_to_check = set()
    for hdr in ["From", "Return-Path", "Reply-To"]:
        val = extracted_headers.get(hdr, "")
        if val and val != "Not Found":
            _, domain = parse_email_address(val)
            if domain:
                domains_to_check.add(domain)
    for url in urls:
        domain_match = re.search(r'https?://(?:www\.)?([^/:]+)', url)
        if domain_match:
            domains_to_check.add(domain_match.group(1).lower())
    typo_findings = check_typosquatting(domains_to_check)
    extracted_headers.setdefault(
        "Typosquat Findings",
        [f.strip('[').strip(' MEDIUM ] HIGH   ] LOW    ]') for f in typo_findings],
    )

    # 4. Social engineering lexicon check
    from social_eng import check_social_engineering
    body_text = re.sub(r'<[^>]+>', ' ', body)
    social_score, social_findings = check_social_engineering(body_text, extracted_headers.get("Subject", ""))
    extracted_headers.setdefault(
        "Social Engineering",
        [f.strip('[').strip(' MEDIUM ] HIGH   ] LOW    ]') for f in social_findings],
    )

    # 5. Received header relay anomaly detection
    from relay import check_relay_anomalies
    relay_findings, relay_score = check_relay_anomalies(
        extracted_headers.get("Received", []),
        extracted_headers.get("From", ""),
    )
    extracted_headers.setdefault(
        "Relay Analysis",
        [f.strip('[').strip(' MEDIUM ] HIGH   ] LOW    ]') for f in relay_findings],
    )

    # 6. Attachment content deep scan
    from attachment import analyze_attachment
    attach_findings = []
    for fname, raw_bytes in attachments_data:
        results = analyze_attachment(fname, raw_bytes)
        for r in results:
            attach_findings.append(f"[ {r['severity']:5s} ] {r['finding']}")
    for att in extracted_headers.get('Attachments', []):
        dangerous_exts = ['.exe', '.js', '.vbs', '.bat', '.cmd', '.scr', '.ps1', '.docm', '.xlsm']
        if any(att.lower().endswith(ext) for ext in dangerous_exts):
            if not any(att in f for f in attach_findings):
                attach_findings.append(f"[ HIGH   ] Dangerous attachment type: {att}")
    extracted_headers.setdefault(
        "Attachment Scan",
        [f.strip('[').strip(' MEDIUM ] HIGH   ] LOW    ]') for f in attach_findings],
    )

    return {
        'headers': extracted_headers,
        'body': body[:1200] + ('...' if len(body) > 1200 else ''),
        'urls': urls,
        'spoof_findings': spoof_findings,
        'typo_findings': typo_findings,
        'social_score': social_score,
        'social_findings': social_findings,
        'relay_findings': relay_findings,
        'relay_score': relay_score,
        'attach_findings': attach_findings,
    }


SEP = "\u2500" * 64


def _print_sections(parsed, urls, vt_results, risk, email_file, is_json):
    import json
    from datetime import datetime

    sections_order = [
        ('spoof_findings', 'SPOOFING ANALYSIS'),
        ('typo_findings', 'HOMOGRAPH / TYPOSQUAT'),
        ('social_findings', 'SOCIAL ENGINEERING  (score +{})'),
        ('relay_findings', 'RELAY CHAIN ANALYSIS'),
        ('attach_findings', 'ATTACHMENT CONTENT SCAN'),
    ]

    for key, label in sections_order:
        findings = parsed.get(key, [])
        if findings:
            if '{}' in label and key == 'social_findings':
                print('\n' + SEP)
                print(f"  {label.format(parsed.get('social_score', 0))}  ({len(findings)} findings)")
            else:
                print('\n' + SEP)
                print(f"  {label}  ({len(findings)} findings)")
            for f_item in findings:
                print(f"  {f_item}")
        elif key == 'relay_findings' and not findings:
            print('\n' + SEP)
            print("  RELAY CHAIN ANALYSIS  (No relay trace)")

    if is_json:
        print(json.dumps({
            "headers": parsed["headers"],
            "urls": urls,
            "vt_results": vt_results,
            "risk_assessment": risk
        }, indent=2))
    else:
        BOX = "\u2550" * 64
        print(BOX)
        print("  PHISHING EMAIL ANALYSER \u2014 THREAT REPORT")
        print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(BOX)
        print()
        print(f"  File   : {email_file}")
        print(f"  From   : {parsed['headers'].get('From', 'N/A')}")
        print(f"  Subject: {parsed['headers'].get('Subject', 'N/A')}")
        print()
        print(SEP)
        print(f"  RISK SCORE: {risk['score']}/100")
        verdict = f"{risk['risk_level']} RISK \u2014 likely phishing" if risk['score'] >= 60 else f"{risk['risk_level']} RISK"
        print(f"  VERDICT   : {verdict}")
        bar_len = int((risk['score'] / 100) * 20)
        bar_fill = '\u2588' * bar_len
        bar_empty = '\u2592' * (20 - bar_len)
        print(f"  {bar_fill}{bar_empty} {risk['risk_level']} RISK")
        print()
        print(SEP)
        print(f"  HEADER ANALYSIS  ({len(risk['findings'])} findings)")
        for finding in risk['findings']:
            print(f"  {finding}")
        print()
        print(SEP)
        print(f"  URL ANALYSIS  ({len(urls)} unique URLs found)")
        if not urls:
            print("  No URLs detected.")
        for url, stats in vt_results.items():
            if "error" in stats or "status" in stats:
                print(f"  - {url} ({stats.get('error', stats.get('status'))})")
            else:
                mark = "\u2717 MALICIOUS" if stats.get("malicious", 0) > 0 else "\u2713 CLEAN"
                print(f"  {mark}")
                print(f"    URL    : {url}")
                print(f"    Engines: {stats.get('malicious',0)} malicious, {stats.get('suspicious',0)} suspicious, {stats.get('harmless',0)} harmless")


if __name__ == "__main__":
    import argparse
    import json
    import io
    import os
    from dotenv import load_dotenv
    from virustotal import scan_urls
    from scoring import calculate_risk_score

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

    _print_sections(parsed, urls, vt_results, risk, args.email, args.json)
