def calculate_risk_score(parsed_data, vt_results):
    score = 0
    max_score = 100
    findings = []
    
    headers = parsed_data.get('headers', {})
    
    # 1. Header Anomalies
    if not headers.get('Message-ID') or headers.get('Message-ID') == 'Not Found':
        score += 10
        findings.append("[ MEDIUM ] Message-ID header missing")
        
    date_header = headers.get('Date', '')
    if not date_header or date_header == 'Not Found':
        score += 5
        findings.append("[ LOW    ] Date header missing")
        
    # 2. Advanced Header Anomalies
    from_header = headers.get('From', '')
    return_path = headers.get('Return-Path', '')
    reply_to = headers.get('Reply-To', '')
    
    from_domain = from_header.split('@')[-1].strip('<> \n').lower() if '@' in from_header else ''
    return_domain = return_path.split('@')[-1].strip('<> \n').lower() if '@' in return_path else ''
    reply_domain = reply_to.split('@')[-1].strip('<> \n').lower() if '@' in reply_to else ''
    
    if from_domain and return_domain and from_domain not in return_domain and return_domain not in from_domain:
        score += 30
        findings.append(f"[ HIGH   ] From/Return-Path mismatch (From: {from_domain} ≠ Return-Path: {return_domain})")
        
    if from_domain and reply_domain and from_domain not in reply_domain and reply_domain not in from_domain:
        score += 30
        findings.append(f"[ HIGH   ] From/Reply-To mismatch (From: {from_domain} ≠ Reply-To: {reply_domain})")
        
    # SPF/DKIM/DMARC checks
    auth_results = headers.get('Authentication-Results', '')
    if auth_results and auth_results != 'Not Found':
        auth_lower = auth_results.lower()
        if 'spf=fail' in auth_lower or 'spf=softfail' in auth_lower:
            score += 20
            findings.append("[ HIGH   ] SPF verification failed")
        elif 'spf=pass' not in auth_lower:
            score += 10
            findings.append("[ MEDIUM ] SPF header missing or inconclusive")
            
        if 'dkim=fail' in auth_lower:
            score += 20
            findings.append("[ HIGH   ] DKIM signature failed")
        elif 'dkim=pass' not in auth_lower:
            score += 10
            findings.append("[ MEDIUM ] DKIM signature missing or inconclusive")
            
        if 'dmarc=fail' in auth_lower:
            score += 20
            findings.append("[ HIGH   ] DMARC verification failed")
    else:
        score += 15
        findings.append("[ MEDIUM ] Authentication-Results header missing (SPF/DKIM/DMARC unknown)")

    # 3. VirusTotal Signals
    malicious_urls_found = 0
    suspicious_urls_found = 0
    
    if isinstance(vt_results, dict):
        for url, stats in vt_results.items():
            if "error" in stats:
                continue
            if "malicious" in stats and stats.get("malicious", 0) > 0:
                malicious_urls_found += int(stats["malicious"])
            elif "suspicious" in stats and stats.get("suspicious", 0) > 0:
                suspicious_urls_found += int(stats["suspicious"])
                
    if malicious_urls_found > 0:
        score += 50
        findings.append(f"[ HIGH   ] {malicious_urls_found} Malicious engine hits detected via VirusTotal URLs")
    elif suspicious_urls_found > 0:
        score += 25
        findings.append(f"[ MEDIUM ] {suspicious_urls_found} Suspicious engine hits detected via VirusTotal URLs")
        
    # 4. Attachment Analysis
    attachments = headers.get('Attachments', [])
    dangerous_extensions = ['.exe', '.js', '.vbs', '.bat', '.cmd', '.scr', '.ps1', '.docm', '.xlsm']
    for att in attachments:
        if any(att.lower().endswith(ext) for ext in dangerous_extensions):
            score += 40
            findings.append(f"[ HIGH   ] Dangerous attachment detected: {att}")
        
    final_score = min(score, max_score)
    
    risk_level = "LOW"
    if final_score >= 60:
        risk_level = "HIGH"
    elif final_score >= 25:
        risk_level = "MEDIUM"
        
    return {
        "score": final_score,
        "max_score": max_score,
        "risk_level": risk_level,
        "malicious_urls": malicious_urls_found,
        "suspicious_urls": suspicious_urls_found,
        "findings": findings
    }
