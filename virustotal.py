import time
import requests
import base64

def scan_urls(urls, api_key):
    """
    Scans a list of URLs using the VirusTotal API.
    Enforces a strict 4 requests/min limit for free tiers by waiting 15s between requests.
    """
    if not api_key:
        return {url: {"error": "Missing VT API Key"} for url in urls}
        
    results = {}
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    # Cap at 5 URLs to prevent massive delays in UI during showcasing
    urls_to_scan = urls[:5]
    
    for i, url in enumerate(urls_to_scan):
        # VT URL ID is url-safe base64 of the URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        try:
            response = requests.get(vt_endpoint, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                results[url] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }
            elif response.status_code == 404:
                results[url] = {"status": "Not found in VT (Unscanned)"}
            elif response.status_code == 429:
                results[url] = {"error": "Rate limit exceeded (429)"}
            else:
                results[url] = {"error": f"API Error {response.status_code}"}
        except Exception as e:
            results[url] = {"error": str(e)}
            
        # Rate limit: Wait 15.5 seconds between requests (except after the last one)
        if i < len(urls_to_scan) - 1:
            time.sleep(15.5)
            
    return results
