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
