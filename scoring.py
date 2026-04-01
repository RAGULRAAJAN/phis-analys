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
        
    # 2. Bulk/Mass Mail sender anomalies
    from_header = headers.get('From', '')
    if "<" not in from_header and "@" in from_header:
        # Simplistic check for properly formatted From headers
        score += 1

    # 3. VirusTotal Signals
    malicious_urls_found = 0
    suspicious_urls_found = 0
    
    if isinstance(vt_results, dict) and "error" not in vt_results:
        for url, stats in vt_results.items():
            if "malicious" in stats and stats["malicious"] > 0:
                malicious_urls_found += 1
            elif "suspicious" in stats and stats["suspicious"] > 0:
                suspicious_urls_found += 1
                
    if malicious_urls_found > 0:
        score += 8  # Immediate high risk
    elif suspicious_urls_found > 0:
        score += 4
        
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
