import json
import re
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

def scan_for_disclosure(url, visited_urls):
    """
    Scan for information disclosure in website content
    
    Args:
        url (str): The base URL to scan
        visited_urls (list): List of URLs visited during crawling
        
    Returns:
        dict: Dictionary containing disclosure findings
    """
    result = {
        'credentials_found': None,
        'pii_found': None,
        'internal_info_found': None,
        'url_secrets_found': None
    }
    
    # Patterns for credential detection
    credential_patterns = {
        'api_key': r'(?i)(api[_-]?key|apikey|authorization)["\s]*[:=]["\s]*([a-zA-Z0-9_\-]{20,})(?:[^a-zA-Z0-9_\-]|$)',
        'aws_key': r'(?i)AKIA[0-9A-Z]{16}',
        'password': r'(?i)(password|passwd|pwd)["\s]*[:=]["\s]*([^\'"\s]{6,})',
        'private_key': r'(?i)-----BEGIN [^\s]+ PRIVATE KEY-----',
        'oauth_token': r'(?i)(access_token|refresh_token)["\s]*[:=]["\s]*([a-zA-Z0-9_\-]{30,})',
        'jwt': r'(?i)(jwt|auth)["\s]*[:=]["\s]*(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)'
    }
    
    # Patterns for PII detection
    pii_patterns = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'(?:\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}',
        'ssn': r'\d{3}-\d{2}-\d{4}',
        'credit_card': r'(?:\d{4}[- ]?){3}\d{4}',
        'address': r'\d+\s+[a-zA-Z0-9\s,]+\b(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|court|ct)\b'
    }
    
    # Patterns for internal information disclosure
    internal_info_patterns = {
        'internal_ip': r'(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)(?:\.[0-9]{1,3}){2}(?:[^0-9]|$)',
        'debug_info': r'(?i)stack trace|debug|exception|error:|traceback|at\s+[\w\.$]+\([^)]*\)',
        'server_path': r'(?i)([a-zA-Z]:\\[^:*?"<>|\r\n]+|/(?:var|etc|usr|home)/[^"\'\s<>]+)',
        'database_info': r'(?i)(mongodb|mysql|postgresql|sqlite)://'
    }
    
    credentials_found = []
    pii_found = []
    internal_info_found = []
    url_secrets_found = []
    
    # Sets to track unique findings and avoid duplicates
    unique_credentials = set()
    unique_pii = set()
    unique_internal_info = set()
    unique_url_secrets = set()
    
    try:
        # First check the base URL for secrets
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Check URL for sensitive parameters
        sensitive_params = ['key', 'api_key', 'apikey', 'password', 'pwd', 'token', 'secret', 'auth']
        for param, values in query_params.items():
            if param.lower() in sensitive_params or any(s in param.lower() for s in sensitive_params):
                # Mask the secret value for security
                value = values[0] if values else ""
                masked_value = mask_sensitive_value(value)
                
                # Determine the type of the secret parameter
                param_type = "api_key" if "api" in param.lower() or "key" in param.lower() else \
                             "token" if "token" in param.lower() else \
                             "password" if "pass" in param.lower() or "pwd" in param.lower() else \
                             "access_key" if "access" in param.lower() else "secret"
                
                # Create a unique identifier for this finding to avoid duplicates
                unique_id = f"{param_type}_{param}_{masked_value}"
                if unique_id not in unique_url_secrets:
                    unique_url_secrets.add(unique_id)
                    url_secrets_found.append({
                        'type': param_type,
                        'url': url,
                        'parameter': param,
                        'masked_value': masked_value
                    })
        
        # Process each visited URL
        for url_data in visited_urls:
            visited_url = url_data.get('url', '')
            content_type = url_data.get('content_type', '')
            
            # Skip non-text content types
            if content_type and not ('text' in content_type or 'json' in content_type or 'xml' in content_type or 'javascript' in content_type):
                continue
            
            try:
                # Check URL for sensitive parameters
                parsed_url = urlparse(visited_url)
                query_params = parse_qs(parsed_url.query)
                
                for param, values in query_params.items():
                    if param.lower() in sensitive_params or any(s in param.lower() for s in sensitive_params):
                        # Mask the secret value for security
                        value = values[0] if values else ""
                        masked_value = mask_sensitive_value(value)
                        
                        # Determine the type of the secret parameter
                        param_type = "api_key" if "api" in param.lower() or "key" in param.lower() else \
                                     "token" if "token" in param.lower() else \
                                     "password" if "pass" in param.lower() or "pwd" in param.lower() else \
                                     "access_key" if "access" in param.lower() else "secret"
                        
                        # Create a unique identifier for this finding to avoid duplicates
                        unique_id = f"{param_type}_{param}_{masked_value}"
                        if unique_id not in unique_url_secrets:
                            unique_url_secrets.add(unique_id)
                            url_secrets_found.append({
                                'type': param_type,
                                'url': visited_url,
                                'parameter': param,
                                'masked_value': masked_value
                            })
                
                # Get page content
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                response = requests.get(visited_url, headers=headers, timeout=10, verify=False)
                content = response.text
                
                # Extract text from HTML
                if 'html' in content_type:
                    soup = BeautifulSoup(content, 'html.parser')
                    text_content = soup.get_text()
                    # Also check script tags separately
                    script_content = ' '.join([script.string for script in soup.find_all('script') if script.string])
                else:
                    text_content = content
                    script_content = ''
                
                # Check for credentials
                for cred_type, pattern in credential_patterns.items():
                    for match in re.finditer(pattern, content):
                        context_text = match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0)
                        unique_id = f"{cred_type}_{context_text}"
                        if unique_id not in unique_credentials:
                            unique_credentials.add(unique_id)
                            credentials_found.append({
                                'type': cred_type,
                                'location': visited_url,
                                'context': context_text
                            })
                    # Also check in script tags
                    if script_content:
                        for match in re.finditer(pattern, script_content):
                            context_text = match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0)
                            # Include script tag in unique ID to differentiate from regular content
                            unique_id = f"{cred_type}_script_{context_text}"
                            if unique_id not in unique_credentials:
                                unique_credentials.add(unique_id)
                                credentials_found.append({
                                    'type': cred_type,
                                    'location': f"{visited_url} (script tag)",
                                    'context': context_text
                                })
                
                # Check for PII
                for pii_type, pattern in pii_patterns.items():
                    for match in re.finditer(pattern, text_content):
                        # Validate based on PII type
                        if pii_type == 'email' and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', match.group(0)):
                            continue
                        if pii_type == 'credit_card' and not is_valid_credit_card(match.group(0).replace(' ', '').replace('-', '')):
                            continue
                        
                        # Use the full PII value as part of the unique identifier
                        context_text = match.group(0)
                        unique_id = f"{pii_type}_{context_text}"
                        if unique_id not in unique_pii:
                            unique_pii.add(unique_id)
                            pii_found.append({
                                'type': pii_type,
                                'location': visited_url,
                                'context': context_text  # Show full PII without truncation
                            })
                
                # Check for internal information
                for info_type, pattern in internal_info_patterns.items():
                    for match in re.finditer(pattern, content):
                        context_text = match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0)
                        unique_id = f"{info_type}_{context_text}"
                        if unique_id not in unique_internal_info:
                            unique_internal_info.add(unique_id)
                            internal_info_found.append({
                                'type': info_type,
                                'location': visited_url,
                                'context': context_text
                            })
            
            except requests.exceptions.RequestException as e:
                logging.error(f"Request error for {visited_url}: {str(e)}")
            except Exception as e:
                logging.error(f"Error processing {visited_url}: {str(e)}")
        
        # Save results
        if credentials_found:
            result['credentials_found'] = json.dumps(credentials_found)
        
        if pii_found:
            result['pii_found'] = json.dumps(pii_found)
        
        if internal_info_found:
            result['internal_info_found'] = json.dumps(internal_info_found)
        
        if url_secrets_found:
            result['url_secrets_found'] = json.dumps(url_secrets_found)
    
    except Exception as e:
        logging.error(f"Error in scan_for_disclosure: {str(e)}")
    
    return result

def mask_sensitive_value(value):
    """
    Mask sensitive values to protect actual data while still showing some context
    
    Args:
        value (str): The sensitive value to mask
        
    Returns:
        str: A masked version of the value
    """
    if not value:
        return "***"
        
    # For very short values, just mask all
    if len(value) <= 4:
        return "*" * len(value)
        
    # For longer values, show first 2 and last 2 characters
    if len(value) <= 8:
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
        
    # For very long values, show first 3 and last 3 with length indicator
    return value[:3] + "*" * 6 + value[-3:] + f" (length: {len(value)})"


def is_valid_credit_card(number):
    """
    Validate a credit card number using the Luhn algorithm
    
    Args:
        number (str): The credit card number to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not number.isdigit():
        return False
    
    # Check length (valid card numbers are typically 13-19 digits)
    if len(number) < 13 or len(number) > 19:
        return False
    
    # Apply Luhn algorithm
    digits = [int(digit) for digit in number]
    checksum = 0
    
    for i in range(len(digits) - 2, -1, -2):
        double = digits[i] * 2
        digits[i] = double if double < 10 else double - 9
    
    checksum = sum(digits)
    
    return checksum % 10 == 0
