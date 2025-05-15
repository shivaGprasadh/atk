import threading
import time
import logging
from app import app, db
from models import Scan, IPScan, DNSScan, SSLScan, HTTPScan, PortScan, WhoisScan, CookieScan, DisclosureScan, VisitedUrl, TechScan

# Import utility modules 
from utils.ip_utils import scan_ip
from utils.dns_utils import scan_dns
from utils.cors_utils import scan_cors
from utils.ssl_utils import scan_ssl
from utils.http_utils import scan_http_headers, check_https_redirect
from utils.port_scanner import scan_ports
from utils.whois_utils import scan_whois
from utils.cookie_utils import scan_cookies
from utils.disclosure_scanner import scan_for_disclosure
from utils.crawler import crawl_website
from utils.tech_utils import analyze_tech_stack

# Thread-local storage for scan progress
scan_progress = {}

def perform_scan(scan_id):
    """Start a scan in a separate thread"""
    thread = threading.Thread(target=_run_scan, args=(scan_id,))
    thread.daemon = True
    thread.start()
    return thread

def _run_scan(scan_id):
    """Run a complete scan on the target"""
    with app.app_context():
        try:
            scan = Scan.query.get(scan_id)
            if not scan:
                logging.error(f"Scan with ID {scan_id} not found")
                return

            target_url = scan.target_url
            logging.info(f"Starting scan for {target_url} (ID: {scan_id})")

            # Initialize progress tracking
            scan_progress[scan_id] = {
                'status': 'running',
                'progress': 0,
                'current_step': 'Starting scan',
                'steps_complete': 0,
                'total_steps': 7  # Updated total number of scan components
            }

            # 1. IP Information
            update_progress(scan_id, 'Scanning IP information')
            ip_data = scan_ip(target_url)
            ip_scan = IPScan(
                scan_id=scan_id,
                ip_address=ip_data.get('ip_address'),
                hostname=ip_data.get('hostname'),
                geolocation=ip_data.get('geolocation'),
                asn_info=ip_data.get('asn_info'),
                is_private=ip_data.get('is_private', False)
            )
            db.session.add(ip_scan)
            db.session.commit()

            # 2. DNS Information
            update_progress(scan_id, 'Scanning DNS information')
            dns_data = scan_dns(target_url)
            dns_scan = DNSScan(
                scan_id=scan_id,
                dns_records=dns_data.get('dns_records'),
                has_dnssec=dns_data.get('has_dnssec', False),
                dnssec_status=dns_data.get('dnssec_status'),
                nameservers=dns_data.get('nameservers')
            )
            db.session.add(dns_scan)
            db.session.commit()

            # 3. SSL Certificate
            update_progress(scan_id, 'Scanning SSL certificate')
            ssl_data = scan_ssl(target_url)
            ssl_scan = SSLScan(
                scan_id=scan_id,
                has_ssl=ssl_data.get('has_ssl', False),
                cert_issuer=ssl_data.get('cert_issuer'),
                cert_subject=ssl_data.get('cert_subject'),
                valid_from=ssl_data.get('valid_from'),
                valid_until=ssl_data.get('valid_until'),
                certificate_version=ssl_data.get('certificate_version'),
                signature_algorithm=ssl_data.get('signature_algorithm'),
                issues=ssl_data.get('issues')
            )
            db.session.add(ssl_scan)
            db.session.commit()

            # 4. HTTP Headers and HTTPS Redirect
            update_progress(scan_id, 'Scanning HTTP headers and redirect')
            http_data = scan_http_headers(target_url)
            redirect_check = check_https_redirect(target_url)
            http_scan = HTTPScan(
                scan_id=scan_id,
                headers=http_data.get('headers'),
                redirect_to_https=redirect_check.get('redirects_to_https', False),
                missing_headers=http_data.get('missing_headers'),
                insecure_headers=http_data.get('insecure_headers'),
                server_info=http_data.get('server_info'),
                csp_issues=http_data.get('csp_issues')
            )
            db.session.add(http_scan)
            db.session.commit()

            # 5. Port Scanning
            update_progress(scan_id, 'Scanning open ports')
            port_data = scan_ports(ip_data.get('ip_address', ''), scan_type='full')
            port_scan = PortScan(
                scan_id=scan_id,
                open_ports=port_data.get('open_ports')
            )
            db.session.add(port_scan)
            db.session.commit()

            # 6. WHOIS Scan
            update_progress(scan_id, 'Scanning WHOIS information')
            whois_data = scan_whois(target_url)
            whois_scan = WhoisScan(
                scan_id=scan_id,
                domain_name=whois_data.get('domain_name'),
                registrar=whois_data.get('registrar'),
                creation_date=whois_data.get('creation_date'),
                expiration_date=whois_data.get('expiration_date'),
                whois_data=whois_data.get('whois_data')
            )
            db.session.add(whois_scan)
            db.session.commit()

            # 7. Cookie Security Scan
            update_progress(scan_id, 'Scanning cookie security')
            cookie_data = scan_cookies(target_url)
            cookie_scan = CookieScan(
                scan_id=scan_id,
                cookies=cookie_data.get('cookies'),
                issues=cookie_data.get('issues')
            )
            db.session.add(cookie_scan)
            db.session.commit()

            # 8. Crawl website and check for information disclosure
            update_progress(scan_id, 'Crawling website and checking for information disclosure')
            visited_urls = crawl_website(target_url)

            # Save visited URLs
            for url_data in visited_urls:
                visited_url = VisitedUrl(
                    scan_id=scan_id,
                    url=url_data.get('url'),
                    status_code=url_data.get('status_code'),
                    content_type=url_data.get('content_type')
                )
                db.session.add(visited_url)

            # Check for information disclosure in visited pages
            disclosure_data = scan_for_disclosure(target_url, visited_urls)
            disclosure_scan = DisclosureScan(
                scan_id=scan_id,
                credentials_found=disclosure_data.get('credentials_found'),
                pii_found=disclosure_data.get('pii_found'),
                internal_info_found=disclosure_data.get('internal_info_found'),
                url_secrets_found=disclosure_data.get('url_secrets_found')
            )
            db.session.add(disclosure_scan)

            # Technology Stack Analysis
            update_progress(scan_id, 'Analyzing technology stack')
            tech_data = analyze_tech_stack(target_url)
            tech_scan = TechScan(
                scan_id=scan_id,
                technologies=tech_data
            )
            db.session.add(tech_scan)
            db.session.commit()

            # Update scan status to complete
            scan.is_complete = True
            scan.recalculate_vulnerability_counts()
            db.session.commit()

            # Update progress
            scan_progress[scan_id] = {
                'status': 'complete',
                'progress': 100,
                'current_step': 'Scan completed',
                'steps_complete': 7,
                'total_steps': 7
            }

            logging.info(f"Scan completed for {target_url} (ID: {scan_id})")

        except Exception as e:
            logging.error(f"Error during scan {scan_id}: {str(e)}")
            scan_progress[scan_id] = {
                'status': 'error',
                'progress': 0,
                'current_step': f'Error: {str(e)}',
                'steps_complete': 0,
                'total_steps': 7
            }
            # Make sure to mark the scan as complete even on error
            scan = Scan.query.get(scan_id)
            if scan:
                scan.is_complete = True
                db.session.commit()

def update_progress(scan_id, current_step):
    """Update the progress of a scan"""
    if scan_id in scan_progress:
        steps_complete = scan_progress[scan_id]['steps_complete'] + 1
        progress = int((steps_complete / scan_progress[scan_id]['total_steps']) * 100)

        scan_progress[scan_id] = {
            'status': 'running',
            'progress': progress,
            'current_step': current_step,
            'steps_complete': steps_complete,
            'total_steps': scan_progress[scan_id]['total_steps']
        }

def get_scan_progress(scan_id):
    """Get the current progress of a scan"""
    if scan_id in scan_progress:
        return scan_progress[scan_id]

    # If no progress info, check if scan exists and is complete
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if scan and scan.is_complete:
            return {
                'status': 'complete',
                'progress': 100,
                'current_step': 'Scan completed',
                'steps_complete': 7,
                'total_steps': 7
            }

    # Default if no info available
    return {
        'status': 'unknown',
        'progress': 0,
        'current_step': 'Unknown',
        'steps_complete': 0,
        'total_steps': 7
    }