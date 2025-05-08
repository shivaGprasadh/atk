import json
import requests
import logging
from urllib.parse import urlparse

def scan_cookies(url):
    """
    Scan cookies for security issues
    
    Args:
        url (str): The URL to scan
        
    Returns:
        dict: Dictionary containing cookie security information
    """
    result = {
        'cookies': None,
        'issues': None
    }
    
    try:
        # Make HTTP request
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        # Get cookies from response
        cookies = response.cookies
        
        # If no cookies are found, try to make another request to follow redirects
        if not cookies:
            response = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
            cookies = response.cookies
        
        if not cookies:
            return result
        
        # Extract cookie information
        cookie_list = []
        issues = []
        
        for cookie in cookies:
            cookie_info = {
                'name': cookie.name,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'expires': cookie.expires,
                'httponly': cookie.has_nonstandard_attr('httponly'),
                'samesite': cookie.get_nonstandard_attr('samesite', None)
            }
            
            cookie_list.append(cookie_info)
            
            # Check for security issues
            
            # Check if secure flag is set
            if not cookie.secure:
                issues.append({
                    'title': f'Cookie Missing Secure Flag: {cookie.name}',
                    'description': 'Cookie is set without the Secure flag, which means it can be transmitted over unencrypted HTTP connections.',
                    'severity': 'high',
                    'recommendation': 'Set the Secure flag for all cookies to ensure they are only sent over HTTPS connections.'
                })
            
            # Check if HttpOnly flag is set
            if not cookie.has_nonstandard_attr('httponly'):
                issues.append({
                    'title': f'Cookie Missing HttpOnly Flag: {cookie.name}',
                    'description': 'Cookie is set without the HttpOnly flag, which means it can be accessed by JavaScript.',
                    'severity': 'medium',
                    'recommendation': 'Set the HttpOnly flag for cookies that don\'t need to be accessed by JavaScript to prevent XSS attacks.'
                })
            
            # Check SameSite attribute
            samesite = cookie.get_nonstandard_attr('samesite', None)
            if not samesite:
                issues.append({
                    'title': f'Cookie Missing SameSite Attribute: {cookie.name}',
                    'description': 'Cookie is set without the SameSite attribute, which may make it vulnerable to CSRF attacks.',
                    'severity': 'medium',
                    'recommendation': 'Set the SameSite attribute to "Strict" or "Lax" to prevent the cookie from being sent in cross-site requests.'
                })
            elif samesite.lower() == 'none' and not cookie.secure:
                issues.append({
                    'title': f'Cookie with SameSite=None Without Secure Flag: {cookie.name}',
                    'description': 'Cookie is set with SameSite=None but without the Secure flag, which is not supported by modern browsers.',
                    'severity': 'high',
                    'recommendation': 'When using SameSite=None, always set the Secure flag as well.'
                })
            
            # Check for cookie prefixes
            if cookie.name.startswith('__Secure-') and not cookie.secure:
                issues.append({
                    'title': f'Invalid __Secure- Cookie Prefix: {cookie.name}',
                    'description': 'Cookie uses the __Secure- prefix but is not set with the Secure flag.',
                    'severity': 'high',
                    'recommendation': 'When using the __Secure- prefix, the cookie must be set with the Secure flag.'
                })
            
            if cookie.name.startswith('__Host-'):
                if not cookie.secure:
                    issues.append({
                        'title': f'Invalid __Host- Cookie Prefix: {cookie.name}',
                        'description': 'Cookie uses the __Host- prefix but is not set with the Secure flag.',
                        'severity': 'high',
                        'recommendation': 'When using the __Host- prefix, the cookie must be set with the Secure flag.'
                    })
                
                if cookie.domain or cookie.path != '/':
                    issues.append({
                        'title': f'Invalid __Host- Cookie Prefix: {cookie.name}',
                        'description': 'Cookie uses the __Host- prefix but has a domain attribute set or path is not "/".',
                        'severity': 'high',
                        'recommendation': 'When using the __Host- prefix, the cookie must not have a domain attribute and the path must be "/".'
                    })
        
        if cookie_list:
            result['cookies'] = json.dumps(cookie_list)
        
        if issues:
            result['issues'] = json.dumps(issues)
    
    except requests.exceptions.RequestException as e:
        logging.error(f"Cookie scan request error: {str(e)}")
    except Exception as e:
        logging.error(f"Error in scan_cookies: {str(e)}")
    
    return result
