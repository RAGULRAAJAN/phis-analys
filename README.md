# Phishing Email Analyser

A defensive security tool that parses `.eml` files, analyses email headers for spoofing indicators, extracts URLs from the body, and checks each URL against the VirusTotal API v3 to produce a threat score and report.

## What it does

| Module | Description |
|---|---|
| **Header analysis** | Detects From/Return-Path/Reply-To domain mismatches, missing SPF/DKIM/DMARC |
| **URL extraction** | Regex-based extraction of all hyperlinks from email body |
| **VirusTotal v3** | Checks each URL against 70+ security engines via VT API v3 |
| **Risk scoring** | Weighted 0–100 score based on all findings |
| **Reports** | Human-readable terminal output + optional JSON report |

## Setup

**1. Install dependencies**
```bash
pip3 install -r requirements.txt
```

**2. Get a free VirusTotal API key**
- Create a free account at [https://www.virustotal.com](https://www.virustotal.com)
- Go to your profile → API Key
- Copy the key (free tier = 4 requests/minute, 500/day)

**3. Run the analyser**
```bash
# Basic run
python3 analyser.py --email sample_phishing.eml --apikey YOUR_VT_KEY

# Also save a JSON report
python3 analyser.py --email sample_phishing.eml --apikey YOUR_VT_KEY --json

# Offline mode — skip VirusTotal (header + body analysis only)
python3 analyser.py --email sample_phishing.eml --apikey dummy --no-vt
```

## Project structure
```text
phishing_analyser/
├── analyser.py           # Main script
├── sample_phishing.eml   # Test email (simulated phishing)
├── app.py                # Optional Web UI server
├── requirements.txt
└── README.md
```

## MITRE ATT&CK mapping

| Detection | Technique |
|---|---|
| From/Return-Path spoofing | T1566.001 — Spearphishing Attachment |
| Missing SPF/DKIM | T1566 — Phishing |
| Malicious URLs in body | T1566.002 — Spearphishing Link |
| Tracking pixel detection | T1598 — Gather Victim Info |