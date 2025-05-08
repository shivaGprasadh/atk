import json
import requests
import logging
import subprocess
from urllib.parse import urlparse

import re

def scan_http_headers(url):
    """
    Scan HTTP headers for security issues

    Args:
        url (str): The URL to scan

    Returns:
        dict: Dictionary containing HTTP header information
    """
    result = {
        'headers': None,
        'missing_headers': None,
        'insecure_headers': None,
        'server_info': None,
        'csp_issues': None,
        'cors_policy': None,
        'has_cors': False,
        'redirect_to_https': False
    }

    # List of security headers to check
    cors_headers = [
        'cross-origin-embedder-policy',
        'cross-origin-opener-policy', 
        'cross-origin-resource-policy',
        'access-control-allow-origin',
        'access-control-allow-methods',
        'access-control-allow-headers',
        'access-control-expose-headers',
        'access-control-max-age',
        'access-control-allow-credentials'
    ]

    security_headers = [
        {
            'name': 'Strict-Transport-Security',
            'description': 'HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS.',
            'severity': 'high',
            'recommendation': 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header.'
        },
        {
            'name': 'Content-Security-Policy',
            'description': 'Content Security Policy (CSP) helps prevent XSS and data injection attacks.',
            'severity': 'high',
            'recommendation': 'Implement a strict Content Security Policy.'
        },
        {
            'name': 'X-Content-Type-Options',
            'description': 'X-Content-Type-Options prevents browsers from MIME-sniffing a response from the declared content-type.',
            'severity': 'medium',
            'recommendation': 'Add "X-Content-Type-Options: nosniff" header.'
        },
        {
            'name': 'X-Frame-Options',
            'description': 'X-Frame-Options protects against clickjacking attacks.',
            'severity': 'medium',
            'recommendation': 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header.'
        },
        {
            'name': 'X-XSS-Protection',
            'description': 'X-XSS-Protection enables the cross-site scripting (XSS) filter in browsers.',
            'severity': 'medium',
            'recommendation': 'Add "X-XSS-Protection: 1; mode=block" header.'
        },
        {
            'name': 'Referrer-Policy',
            'description': 'Referrer-Policy controls how much referrer information is included with requests.',
            'severity': 'low',
            'recommendation': 'Add "Referrer-Policy: no-referrer" or "Referrer-Policy: same-origin" header.'
        },
        {
            'name': 'Feature-Policy',
            'description': 'Feature-Policy allows restricting which browser features can be used.',
            'severity': 'low',
            'recommendation': 'Implement a Feature-Policy header to restrict unnecessary browser features.'
        },
        {
            'name': 'Permissions-Policy',
            'description': 'Permissions-Policy (replacement for Feature-Policy) restricts which browser features can be used.',
            'severity': 'low',
            'recommendation': 'Implement a Permissions-Policy header to restrict unnecessary browser features.'
        }
    ]

    try:
        # Use curl to get headers with specified options
        command = [
            'curl', '-s', '-D', '-', '-o', '/dev/null',
            '--http1.1', '-L', '-k',
            '--retry', '3',
            '--retry-delay', '2',
            '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            '-H', 'Accept-Language: en-US,en;q=0.5',
            '-H', 'Connection: keep-alive',
            url
        ]
        try:
            process = subprocess.run(command, capture_output=True, text=True, check=False)
            if process.returncode != 0:
                # Try HTTPS if HTTP fails
                https_url = url.replace('http://', 'https://')
                process = subprocess.run(command[:-1] + [https_url], capture_output=True, text=True, check=True)

            # Parse headers from stdout where curl -D outputs them
            headers = {}
            cors_policy = {}
            header_lines = process.stdout.split('\n')
            in_response_headers = False

            # Use regex to parse headers more accurately
            header_pattern = re.compile(r'^([\w-]+):\s*(.+)$', re.I)
            redirect_pattern = re.compile(r'^HTTP/\d\.\d\s+30[12378]\s+')
            location_pattern = re.compile(r'^location:\s*(https?://[^\s]+)', re.I)
            
            for line in header_lines:
                line = line.strip()
                
                # Check for redirects
                if redirect_pattern.match(line):
                    in_response_headers = True
                    continue
                    
                # Parse headers
                header_match = header_pattern.match(line)
                if header_match:
                    key = header_match.group(1).lower()
                    value = header_match.group(2).strip()
                    headers[key] = value
                    
                    # Check for HTTPS redirect in Location header
                    if key == 'location':
                        loc_match = location_pattern.match(line)
                        if loc_match and 'https://' in loc_match.group(1):
                            result['redirect_to_https'] = True
                    
                    # Check for CORS headers
                    if key.startswith('cross-origin-') or key.startswith('access-control-'):
                        cors_policy[key] = value
                        result['cors_policy'] = json.dumps(cors_policy)
                        result['has_cors'] = True
                        
                elif line == '': # Empty line marks end of headers
                    in_response_headers = False

        except subprocess.CalledProcessError as e:
            logging.error(f"Curl command failed: {e.stderr}")
            headers = {}
            cors_policy = {}

        result['headers'] = json.dumps(headers)
        if cors_policy:
            result['cors_policy'] = json.dumps(cors_policy)


        # Check for missing security headers
        missing_headers = []
        for header in security_headers:
            # Special case for Content-Security-Policy - don't list it as missing if we have CSP-Report-Only
            if header['name'] == 'Content-Security-Policy':
                # Check different case variations of the Content-Security-Policy header
                csp_header_present = False
                for resp_header in headers.keys():
                    if resp_header.lower() == 'content-security-policy' or resp_header.lower() == 'content-security-policy-report-only':
                        csp_header_present = True
                        break
                if not csp_header_present:
                    missing_headers.append(header)
            elif header['name'] not in headers:
                # Check for case-insensitive matches for other headers
                header_present = False
                for resp_header in headers.keys():
                    if resp_header.lower() == header['name'].lower():
                        header_present = True
                        break
                if not header_present:
                    missing_headers.append(header)

        if missing_headers:
            result['missing_headers'] = json.dumps(missing_headers)

        # Check for insecure header configurations
        insecure_headers = []

        # Check HSTS configuration
        if 'Strict-Transport-Security' in headers:
            hsts_header = headers['Strict-Transport-Security']
            if 'max-age=' not in hsts_header.lower():
                insecure_headers.append({
                    'name': 'Strict-Transport-Security',
                    'description': 'HSTS header is missing max-age directive.',
                    'severity': 'medium',
                    'recommendation': 'Ensure the HSTS header includes a max-age directive with a value of at least 31536000 (1 year).'
                })
            elif 'includesubdomains' not in hsts_header.lower():
                insecure_headers.append({
                    'name': 'Strict-Transport-Security',
                    'description': 'HSTS header is missing includeSubDomains directive.',
                    'severity': 'low',
                    'recommendation': 'Add the includeSubDomains directive to the HSTS header to protect all subdomains.'
                })

        # Check X-Frame-Options configuration
        if 'X-Frame-Options' in headers:
            xfo_header = headers['X-Frame-Options'].upper()
            if xfo_header not in ['DENY', 'SAMEORIGIN']:
                insecure_headers.append({
                    'name': 'X-Frame-Options',
                    'description': f'Potentially insecure X-Frame-Options value: {xfo_header}',
                    'severity': 'medium',
                    'recommendation': 'Use either DENY or SAMEORIGIN for the X-Frame-Options header.'
                })

        # Check for Server header (information disclosure)
        if 'Server' in headers:
            result['server_info'] = headers['Server']
            insecure_headers.append({
                'name': 'Server',
                'description': f'Server header reveals version information: {headers["Server"]}',
                'severity': 'low',
                'recommendation': 'Configure the web server to not disclose version information in the Server header.'
            })

        # Check Content Security Policy configuration
        csp_issues = []

        # Find CSP header with case-insensitive match
        csp_header_key = None
        csp_report_only_key = None

        for header_key in headers.keys():
            if header_key.lower() == 'content-security-policy':
                csp_header_key = header_key
            elif header_key.lower() == 'content-security-policy-report-only':
                csp_report_only_key = header_key

        if csp_header_key:
            csp_header = headers[csp_header_key]
            csp_issues = analyze_csp(csp_header)
        elif csp_report_only_key:
            csp_header = headers[csp_report_only_key]
            csp_issues = analyze_csp(csp_header)
            csp_issues.append({
                'name': 'CSP-Report-Only',
                'description': 'Content Security Policy is in report-only mode and not enforced',
                'severity': 'medium',
                'recommendation': 'Switch from Content-Security-Policy-Report-Only to Content-Security-Policy for enforcement'
            })

        if csp_issues:
            result['csp_issues'] = json.dumps(csp_issues)

        if insecure_headers:
            result['insecure_headers'] = json.dumps(insecure_headers)

    except subprocess.CalledProcessError as e:
        result['headers'] = json.dumps({"error": f"Curl command failed: {e.stderr}"})
        result['missing_headers'] = json.dumps([])
        result['insecure_headers'] = json.dumps([])
        result['server_info'] = None
        result['csp_issues'] = json.dumps([])
        logging.error(f"Curl error scanning headers: {str(e)}")
        return result
    except Exception as e:
        logging.error(f"Error in scan_http_headers: {str(e)}")

    return result

def check_https_redirect(url):
    """
    Check if HTTP redirects to HTTPS using curl

    Args:
        url (str): The URL to check

    Returns:
        dict: Dictionary containing redirect information
    """
    result = {
        'redirects_to_https': False
    }
    
    # Parse URL and ensure we test HTTP
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc or parsed_url.path
    test_url = f"http://{hostname}"
    
    try:
        # Use curl to follow redirects and check final URL
        command = [
            'curl', '-sIL', '-o', '/dev/null', '-w', '%{url_effective}', 
            '--max-time', '10',
            '--retry', '2',
            test_url
        ]
        
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        
        if process.returncode == 0 and 'https://' in process.stdout:
            result['redirects_to_https'] = True
            return result
            
        # Check HSTS header as alternative indicator
        command = ['curl', '-sI', test_url]
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        
        if 'strict-transport-security' in process.stdout.lower():
            result['redirects_to_https'] = True
            
    except Exception as e:
        logging.error(f"HTTPS redirect check error: {str(e)}")
        
    return result

    try:
        # Ensure URL uses HTTP
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc or parsed_url.path
        http_url = f"http://{hostname}"

        # Use curl to check redirection with headers only
        command = [
            'curl', '-ILk',
            '-A', 'Mozilla/5.0',
            '--max-time', '30',
            '--connect-timeout', '10',
            '--retry', '3',
            '--retry-delay', '2',
            http_url
        ]

        try:
            process = subprocess.run(command, capture_output=True, text=True, check=True)

            # Parse headers from the output
            headers = {}
            for line in process.stdout.split('\n'):
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                elif line.startswith('HTTP/'):
                    # Store status code for each redirect
                    status_line = line.split(' ')
                    if len(status_line) >= 2:
                        status_code = int(status_line[1])
                        if status_code in [301, 302, 307, 308]:
                            # Check Location header for HTTPS
                            location = headers.get('location', '')
                            if (location.startswith('https://') or 
                                ':443' in location or 
                                (location.startswith('/') and 'location' in headers)):
                                result['redirects_to_https'] = True
                                break

            # Additional check for HSTS header
            if 'strict-transport-security' in headers:
                result['redirects_to_https'] = True

        except subprocess.CalledProcessError as e:
            logging.error(f"Curl command failed: {e.stderr}")
            # Some servers close HTTP connections as security measure
            if "reset by peer" in str(e.stderr):
                result['redirects_to_https'] = True

        # First try HEAD request with shorter timeout
        try:
            response = requests.head(http_url, 
                                  timeout=5,
                                  allow_redirects=True,
                                  verify=False,
                                  headers=headers)
            if response.url.startswith('https://'):
                result['redirects_to_https'] = True
                return result
        except requests.exceptions.RequestException:
            pass

        # If HEAD fails, try GET request
        response = requests.get(http_url,
                              timeout=10,
                              allow_redirects=True,
                              verify=False,
                              headers=headers,
                              stream=True)

        # Check redirect history and final URL
        # First check HTTPS availability
        https_url = url.replace('http://', 'https://')
        try:
            https_response = requests.head(https_url, 
                                        timeout=5,
                                        verify=False,
                                        headers=headers,
                                        allow_redirects=True)
            if https_response.status_code < 400:
                # Site supports HTTPS, now check if HTTP redirects to it
                try:
                    http_url = url.replace('https://', 'http://')
                    http_response = requests.head(http_url,
                                               timeout=5,
                                               verify=False,
                                               headers=headers,
                                               allow_redirects=True)

                    # Check redirect chain
                    if http_response.history:
                        for r in http_response.history:
                            if r.status_code in [301, 302, 307, 308]:
                                location = r.headers.get('Location', '')
                                if location.startswith('https://') or \
                                   (location.startswith('/') and http_response.url.startswith('https://')):
                                    result['redirects_to_https'] = True
                                    break

                    # Check final URL
                    if http_response.url.startswith('https://'):
                        result['redirects_to_https'] = True

                    # Check HSTS header
                    if 'Strict-Transport-Security' in http_response.headers:
                        result['redirects_to_https'] = True

                except requests.exceptions.RequestException as e:
                    if "Connection refused" in str(e) or \
                       "Connection reset by peer" in str(e):
                        # Some servers close HTTP connections as a security measure
                        result['redirects_to_https'] = True

        except requests.exceptions.RequestException:
            pass  # HTTPS not available

    except requests.exceptions.RequestException as e:
        logging.error(f"HTTP redirect check error: {str(e)}")
        if "Remote end closed connection" in str(e):
            # Some servers close connection on HTTP as security measure
            # Try direct HTTPS to verify if HTTPS is supported
            try:
                https_url = f"https://{hostname}"
                response = requests.head(https_url, timeout=5, verify=False, headers=headers)
                if response.status_code < 400:
                    result['redirects_to_https'] = True
            except:
                pass
    except Exception as e:
        logging.error(f"Error in check_https_redirect: {str(e)}")

    return result


def analyze_csp(csp_header):
    """
    Analyze Content Security Policy (CSP) header for common misconfigurations

    Args:
        csp_header (str): The CSP header value to analyze

    Returns:
        list: List of CSP issues found
    """
    issues = []

    # Parse the CSP directives
    directives = {}
    for part in csp_header.split(';'):
        if not part.strip():
            continue

        parts = part.strip().split(' ', 1)
        directive = parts[0].strip().lower()

        if len(parts) > 1:
            values = parts[1].strip().split(' ')
            directives[directive] = values
        else:
            directives[directive] = []

    # Check for unsafe-inline in script-src or style-src
    for directive in ['script-src', 'script-src-elem', 'script-src-attr']:
        if directive in directives and "'unsafe-inline'" in [v.lower() for v in directives[directive]]:
            issues.append({
                'name': 'Unsafe Inline Scripts',
                'description': f"'{directive}' allows inline scripts with 'unsafe-inline', which can lead to XSS attacks",
                'severity': 'high',
                'recommendation': "Remove 'unsafe-inline' from script sources and use nonces or hashes instead"
            })

    for directive in ['style-src', 'style-src-elem', 'style-src-attr']:
        if directive in directives and "'unsafe-inline'" in [v.lower() for v in directives[directive]]:
            issues.append({
                'name': 'Unsafe Inline Styles',
                'description': f"'{directive}' allows inline styles with 'unsafe-inline', which increases XSS risk",
                'severity': 'medium',
                'recommendation': "Remove 'unsafe-inline' from style sources and use nonces or hashes instead"
            })

    # Check for unsafe-eval
    if 'script-src' in directives and "'unsafe-eval'" in [v.lower() for v in directives['script-src']]:
        issues.append({
            'name': 'Unsafe Eval Usage',
            'description': "script-src allows 'unsafe-eval', which can execute arbitrary code",
            'severity': 'high',
            'recommendation': "Remove 'unsafe-eval' and refactor code to avoid using eval(), new Function(), etc."
        })

    # Check for wildcards in critical directives
    critical_directives = ['script-src', 'script-src-elem', 'object-src', 'frame-src', 'connect-src']

    for directive in critical_directives:
        if directive in directives and '*' in directives[directive]:
            issues.append({
                'name': f'Wildcard in {directive}',
                'description': f"{directive} uses a wildcard (*), allowing resources from any domain",
                'severity': 'high',
                'recommendation': f"Replace the wildcard in {directive} with specific domain names"
            })

    # Check if default-src is missing or uses wildcards
    if 'default-src' not in directives:
        issues.append({
            'name': 'Missing default-src',
            'description': "No default-src directive specified, which may allow unintended content",
            'severity': 'medium',
            'recommendation': "Add 'default-src' directive with appropriate restrictions"
        })
    elif '*' in directives['default-src']:
        issues.append({
            'name': 'Permissive default-src',
            'description': "default-src uses a wildcard (*), allowing resources from any domain by default",
            'severity': 'high',
            'recommendation': "Replace the wildcard in default-src with specific domain names or 'self'"
        })

    # Check for missing object-src and base-uri directives
    if 'object-src' not in directives and 'default-src' not in directives:
        issues.append({
            'name': 'Missing object-src',
            'description': "No object-src directive specified, which may allow embedding of unwanted objects",
            'severity': 'medium',
            'recommendation': "Add 'object-src none' to block Flash and other plugins"
        })

    if 'base-uri' not in directives:
        issues.append({
            'name': 'Missing base-uri',
            'description': "No base-uri directive specified, which allows attackers to inject base tags",
            'severity': 'medium',
            'recommendation': "Add 'base-uri 'self'' or 'base-uri 'none'' to restrict base URI manipulation"
        })

    # Check for report-uri/report-to
    if 'report-uri' not in directives and 'report-to' not in directives:
        issues.append({
            'name': 'No Reporting Configured',
            'description': "No CSP violation reporting is configured (missing report-uri or report-to)",
            'severity': 'low',
            'recommendation': "Add 'report-to' or 'report-uri' directive to collect CSP violation reports"
        })

    # Check for upgrade-insecure-requests
    if 'upgrade-insecure-requests' not in directives:
        issues.append({
            'name': 'Missing upgrade-insecure-requests',
            'description': "No upgrade-insecure-requests directive, which automatically upgrades HTTP to HTTPS",
            'severity': 'medium',
            'recommendation': "Add 'upgrade-insecure-requests' directive to ensure secure connections"
        })

    return issues