def calculate_risk_score(parsed_data, vt_results):
    score = 0
    max_score = 10
    
    headers = parsed_data.get('headers', {})
    
    # 1. Header Anomalies (Max +3)
    if not headers.get('Message-ID') or headers.get('Message-ID') == 'Not Found':
        score += 2
        
    date_header = headers.get('Date', '')
    if not date_header or date_header == 'Not Found':
        score += 1
        
    # 2. Advanced Header Anomalies
    from_header = headers.get('From', '')
    message_id = headers.get('Message-ID', '')
    
    # Domain mismatch check
    from_domain = from_header.split('@')[-1].strip('<> \n').lower() if '@' in from_header else ''
    msg_domain = message_id.split('@')[-1].strip('<> \n').lower() if '@' in message_id else ''
    
    if from_domain and msg_domain and from_domain not in msg_domain and msg_domain not in from_domain:
        score += 3 # Strong phishing indicator
        
    # SPF/DKIM/DMARC checks
    auth_results = headers.get('Authentication-Results', '')
    if auth_results and auth_results != 'Not Found':
        auth_lower = auth_results.lower()
        if 'spf=fail' in auth_lower or 'spf=softfail' in auth_lower:
            score += 2
        if 'dkim=fail' in auth_lower:
            score += 2
        if 'dmarc=fail' in auth_lower:
            score += 2

    # 3. VirusTotal Signals
    malicious_urls_found = 0
    suspicious_urls_found = 0
    
    if isinstance(vt_results, dict):
        for url, stats in vt_results.items():
            if "error" in stats:
                continue
            if "malicious" in stats and stats.get("malicious", 0) > 0:
                malicious_urls_found += 1
            elif "suspicious" in stats and stats.get("suspicious", 0) > 0:
                suspicious_urls_found += 1
                
    if malicious_urls_found > 0:
        score += 8  # Immediate high risk
    elif suspicious_urls_found > 0:
        score += 4
        
    # 4. Attachment Analysis
    attachments = headers.get('Attachments', [])
    dangerous_extensions = ['.exe', '.js', '.vbs', '.bat', '.cmd', '.scr', '.ps1', '.docm', '.xlsm']
    for att in attachments:
        if any(att.lower().endswith(ext) for ext in dangerous_extensions):
            score += 5 # Highly suspicious attachment
        
    # Cap score at 10
    final_score = min(score, max_score)
    
    # Risk Level mapping
    risk_level = "Low"
    if final_score >= 8:
        risk_level = "Critical"
    elif final_score >= 5:
        risk_level = "High"
    elif final_score >= 3:
        risk_level = "Medium"
        
    return {
        "score": final_score,
        "max_score": max_score,
        "risk_level": risk_level,
        "malicious_urls": malicious_urls_found,
        "suspicious_urls": suspicious_urls_found
    }
