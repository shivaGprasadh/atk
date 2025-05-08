import json
import socket
import ssl
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def fetch_certificate(domain, port=443):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    conn.settimeout(5.0)
    conn.connect((domain, port))
    der_cert = conn.getpeercert(binary_form=True)
    conn.close()
    return der_cert

def parse_certificate(der_cert):
    cert = x509.load_der_x509_certificate(der_cert, default_backend())
    now = datetime.now(timezone.utc)
    days_left = (cert.not_valid_after_utc - now).days

    return {
        'has_ssl': True,
        'cert_subject': cert.subject.rfc4514_string(),
        'cert_issuer': cert.issuer.rfc4514_string(),
        'signature_algorithm': cert.signature_hash_algorithm.name,
        'valid_from': cert.not_valid_before_utc,
        'valid_until': cert.not_valid_after_utc,
        'days_until_expiry': days_left,
        'certificate_version': f"v{cert.version.value}",
        'sha256_fingerprint': cert.fingerprint(hashes.SHA256()).hex().upper(),
        'sha1_fingerprint': cert.fingerprint(hashes.SHA1()).hex().upper(),
        'public_key_type': cert.public_key().__class__.__name__,
        'public_key_size': getattr(cert.public_key(), "key_size", "Unknown"),
        'issues': None
    }

def scan_ssl(url):
    """
    Scan SSL certificate information for a given URL
    """
    result = {
        'has_ssl': False,
        'cert_issuer': None,
        'cert_subject': None,
        'valid_from': None,
        'valid_until': None,
        'certificate_version': None,
        'signature_algorithm': None,
        'issues': None
    }

    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'https://' + url
            parsed_url = urlparse(url)

        hostname = parsed_url.netloc
        if ':' in hostname:
            hostname, port = hostname.split(':')
            port = int(port)
        else:
            port = 443

        if hostname.startswith('www.'):
            hostname = hostname[4:]

        logging.debug(f"Scanning SSL for hostname: {hostname}")

        der_cert = fetch_certificate(hostname, port)
        result.update(parse_certificate(der_cert))

    except (ssl.SSLError, socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
        logging.error(f"SSL Error: {str(e)}")
        result['has_ssl'] = False
        result['issues'] = [{
            'title': 'SSL Certificate Error',
            'description': f'SSL error occurred: {str(e)}',
            'severity': 'high',
            'recommendation': 'Check and fix SSL certificate configuration.'
        }]
    except Exception as e:
        logging.error(f"Error in scan_ssl: {str(e)}")
        result['has_ssl'] = False

    return result