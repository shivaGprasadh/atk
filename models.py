import datetime
import json
from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    scans = db.relationship('Scan', backref='user', lazy='dynamic')


class Scan(db.Model):
    __tablename__ = 'scans'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    target_url = db.Column(db.String(2048), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_complete = db.Column(db.Boolean, default=False)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)

    # Relationships
    ip_scan = db.relationship('IPScan', backref='scan', uselist=False, cascade='all, delete-orphan')
    dns_scan = db.relationship('DNSScan', backref='scan', uselist=False, cascade='all, delete-orphan')
    ssl_scan = db.relationship('SSLScan', backref='scan', uselist=False, cascade='all, delete-orphan')
    http_scan = db.relationship('HTTPScan', backref='scan', uselist=False, cascade='all, delete-orphan')
    port_scan = db.relationship('PortScan', backref='scan', uselist=False, cascade='all, delete-orphan')
    whois_scan = db.relationship('WhoisScan', backref='scan', uselist=False, cascade='all, delete-orphan')
    cookie_scan = db.relationship('CookieScan', backref='scan', uselist=False, cascade='all, delete-orphan')
    disclosure_scan = db.relationship('DisclosureScan', backref='scan', uselist=False, cascade='all, delete-orphan')
    tech_scan = db.relationship('TechScan', backref='scan', uselist=False, cascade='all, delete-orphan')
    visited_urls = db.relationship('VisitedUrl', backref='scan', cascade='all, delete-orphan')

    def recalculate_vulnerability_counts(self):
        """Recalculate vulnerability counts based on findings"""
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        self.info_count = 0

        # Get findings from all scan components
        scan_components = [
            self.ip_scan, self.dns_scan, self.ssl_scan, self.http_scan,
            self.port_scan, self.whois_scan, self.cookie_scan,
            self.disclosure_scan, self.tech_scan
        ]

        for component in scan_components:
            if component:
                findings = component.get_findings()
                for finding in findings:
                    severity = finding.get('severity', 'info').lower()
                    if severity == 'critical':
                        self.critical_count += 1
                    elif severity == 'high':
                        self.high_count += 1
                    elif severity == 'medium':
                        self.medium_count += 1
                    elif severity == 'low':
                        self.low_count += 1
                    else:
                        self.info_count += 1


class IPScan(db.Model):
    __tablename__ = 'ip_scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    ip_address = db.Column(db.String(45))  # Accommodate IPv6
    hostname = db.Column(db.String(255))
    geolocation = db.Column(db.Text)  # Store JSON data for geolocation
    asn_info = db.Column(db.Text)  # Store JSON data for ASN info
    is_private = db.Column(db.Boolean)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def get_findings(self):
        findings = []
        if self.ip_address:
            findings.append({
                'title': 'IP Information',
                'description': f'Target IP: {self.ip_address}',
                'severity': 'info'
            })
        if self.is_private:
            findings.append({
                'title': 'Private IP Detected',
                'description': f'The target IP {self.ip_address} is a private address, which may indicate an internal service.',
                'severity': 'medium',
                'recommendation': 'Ensure that internal services are not directly exposed to the public internet.'
            })
        return findings


class DNSScan(db.Model):
    __tablename__ = 'dns_scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    dns_records = db.Column(db.Text)  # Store JSON data for DNS records
    has_dnssec = db.Column(db.Boolean)
    dnssec_status = db.Column(db.String(50))
    nameservers = db.Column(db.Text)  # Store JSON array of nameservers
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def get_findings(self):
        findings = []
        if not self.has_dnssec:
            findings.append({
                'title': 'DNSSEC Not Enabled',
                'description': 'Domain does not have DNSSEC enabled which could allow DNS spoofing attacks.',
                'severity': 'medium',
                'recommendation': 'Enable DNSSEC to protect against DNS spoofing attacks.'
            })
        elif self.dnssec_status != 'valid':
            findings.append({
                'title': 'DNSSEC Configuration Issue',
                'description': f'DNSSEC is enabled but shows status: {self.dnssec_status}',
                'severity': 'high',
                'recommendation': 'Verify and fix DNSSEC configuration.'
            })
        if self.nameservers:
            nameservers = json.loads(self.nameservers)
            if len(nameservers) < 2:
                findings.append({
                    'title': 'Insufficient Nameservers',
                    'description': 'Domain has less than two nameservers which creates a single point of failure.',
                    'severity': 'medium',
                    'recommendation': 'Configure at least two nameservers for redundancy.'
                })
        if self.dns_records:
            findings.append({
                'title': 'DNS Records',
                'description': 'DNS records found for the domain.',
                'severity': 'info',
                'details': json.loads(self.dns_records)
            })
        return findings


class SSLScan(db.Model):
    __tablename__ = 'ssl_scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    has_ssl = db.Column(db.Boolean)
    cert_issuer = db.Column(db.String(255))
    cert_subject = db.Column(db.String(255))
    valid_from = db.Column(db.DateTime)
    valid_until = db.Column(db.DateTime)
    certificate_version = db.Column(db.String(20))
    signature_algorithm = db.Column(db.String(50))
    issues = db.Column(db.Text)  # Store JSON array of issues
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def get_findings(self):
        findings = []
        if not self.has_ssl:
            findings.append({
                'title': 'No SSL Certificate',
                'description': 'The website does not have an SSL certificate which exposes it to man-in-the-middle attacks.',
                'severity': 'high',
                'recommendation': 'Install an SSL certificate and configure HTTPS.'
            })
            return findings
        now = datetime.datetime.utcnow()
        if self.valid_until:
            days_until_expiry = (self.valid_until - now).days
            if days_until_expiry < 0:
                findings.append({
                    'title': 'SSL Certificate Expired',
                    'description': f'The SSL certificate expired {abs(days_until_expiry)} days ago.',
                    'severity': 'critical',
                    'recommendation': 'Renew the SSL certificate immediately.'
                })
            elif days_until_expiry < 30:
                findings.append({
                    'title': 'SSL Certificate Expiring Soon',
                    'description': f'The SSL certificate will expire in {days_until_expiry} days.',
                    'severity': 'high',
                    'recommendation': 'Renew the SSL certificate soon.'
                })
        weak_algorithms = ['sha1', 'md5']
        if self.signature_algorithm and any(weak in self.signature_algorithm.lower() for weak in weak_algorithms):
            findings.append({
                'title': 'Weak Signature Algorithm',
                'description': f'The SSL certificate uses a weak signature algorithm: {self.signature_algorithm}',
                'severity': 'high',
                'recommendation': 'Obtain a new certificate with a stronger signature algorithm (SHA-256 or better).'
            })
        if self.issues:
            issue_list = json.loads(self.issues)
            for issue in issue_list:
                findings.append({
                    'title': issue.get('title', 'SSL Issue'),
                    'description': issue.get('description', 'An SSL issue was detected.'),
                    'severity': issue.get('severity', 'medium'),
                    'recommendation': issue.get('recommendation', 'Review the SSL configuration.')
                })
        findings.append({
            'title': 'SSL Certificate Information',
            'description': f'Issuer: {self.cert_issuer}, Subject: {self.cert_subject}, ' +
                          f'Valid from {self.valid_from} to {self.valid_until}',
            'severity': 'info'
        })
        return findings


class HTTPScan(db.Model):
    __tablename__ = 'http_scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    headers = db.Column(db.Text)  # Store JSON data for headers
    redirect_to_https = db.Column(db.Boolean)
    missing_headers = db.Column(db.Text)  # Store JSON array of missing security headers
    insecure_headers = db.Column(db.Text)  # Store JSON array of insecure headers
    server_info = db.Column(db.String(255))  # Server information if disclosed
    csp_issues = db.Column(db.Text)  # Store JSON array of CSP misconfigurations
    cors_findings = db.Column(db.Text) # Added CORS findings field
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def get_findings(self):
        findings = []
        if not self.redirect_to_https:
            findings.append({
                'title': 'No HTTP to HTTPS Redirection',
                'description': 'The website does not redirect HTTP traffic to HTTPS, potentially allowing unencrypted communication.',
                'severity': 'high',
                'recommendation': 'Configure HTTP to HTTPS redirection on your web server.'
            })
        if self.missing_headers:
            missing = json.loads(self.missing_headers)
            for header in missing:
                findings.append({
                    'title': f'Missing Security Header: {header["name"]}',
                    'description': header.get('description', f'The security header {header["name"]} is missing.'),
                    'severity': header.get('severity', 'medium'),
                    'recommendation': header.get('recommendation', f'Add the {header["name"]} header to your responses.')
                })
        if self.insecure_headers:
            insecure = json.loads(self.insecure_headers)
            for header in insecure:
                findings.append({
                    'title': f'Insecure Header Configuration: {header["name"]}',
                    'description': header.get('description', f'The header {header["name"]} is configured insecurely.'),
                    'severity': header.get('severity', 'medium'),
                    'recommendation': header.get('recommendation', f'Fix the configuration of the {header["name"]} header.')
                })
        if self.server_info:
            findings.append({
                'title': 'Server Information Disclosure',
                'description': f'The server is disclosing version information: {self.server_info}',
                'severity': 'low',
                'recommendation': 'Configure your server to not reveal version information in HTTP headers.'
            })
        if self.csp_issues:
            csp_issues = json.loads(self.csp_issues)
            for issue in csp_issues:
                findings.append({
                    'title': f'CSP Misconfiguration: {issue.get("name", "Unknown Issue")}',
                    'description': issue.get('description', 'A Content Security Policy misconfiguration was detected.'),
                    'severity': issue.get('severity', 'medium'),
                    'recommendation': issue.get('recommendation', 'Review and correct Content Security Policy configuration.')
                })

        # Add CORS findings
        if hasattr(self, 'cors_findings') and self.cors_findings:
            cors_data = json.loads(self.cors_findings)
            for finding in cors_data:
                # Wildcard Origin with Credentials check
                if finding.get('acao_header') == '*' and finding.get('acac_header', '').lower() == 'true':
                    findings.append({
                        'title': 'CORS: Wildcard Origin with Credentials',
                        'description': 'The server allows all origins (*) while also enabling credentials, which is an invalid and insecure combination.',
                        'severity': 'high',
                        'recommendation': 'Specify exact allowed origins instead of using wildcard when credentials are enabled.'
                    })

                # Null Origin check
                if finding.get('acao_header', '').lower() == 'null':
                    findings.append({
                        'title': 'CORS: Null Origin Allowed',
                        'description': 'The server allows requests from null origin, which can be exploited via sandboxed iframes.',
                        'severity': 'medium',
                        'recommendation': 'Remove null from allowed origins unless specifically required.'
                    })

                # Wildcard in Headers/Methods
                if finding.get('acah_header') == '*' or finding.get('acam_header') == '*':
                    findings.append({
                        'title': 'CORS: Overly Permissive Headers/Methods',
                        'description': 'The server uses wildcards for allowed headers or methods, which may allow unsafe client behavior.',
                        'severity': 'medium',
                        'recommendation': 'Explicitly specify allowed headers and methods instead of using wildcards.'
                    })

                # Missing Vary Header for Dynamic Origins
                if finding.get('acao_header') != '*' and 'vary' not in [h.lower() for h in finding.get('headers', {})]:
                    findings.append({
                        'title': 'CORS: Missing Vary Header',
                        'description': 'Dynamic CORS origin handling without Vary: Origin header can lead to cache poisoning.',
                        'severity': 'medium',
                        'recommendation': 'Add Vary: Origin header when handling dynamic CORS origins.'
                    })

                # Private/Localhost Origins
                origin = finding.get('acao_header', '')
                if any(x in origin for x in ['localhost', '127.0.0.1', '192.168.', '10.', '172.']):
                    findings.append({
                        'title': 'CORS: Private Origins Allowed',
                        'description': f'The server accepts private/localhost origins: {origin}',
                        'severity': 'high',
                        'recommendation': 'Remove private network origins from allowed CORS origins.'
                    })

        return findings


class PortScan(db.Model):
    __tablename__ = 'port_scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    open_ports = db.Column(db.Text)  # Store JSON array of open ports and services
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def get_findings(self):
        findings = []
        if not self.open_ports:
            return findings
        open_ports = json.loads(self.open_ports)
        if open_ports:
            findings.append({
                'title': 'Open Ports Detected',
                'description': f'Found {len(open_ports)} open ports on the target host.',
                'severity': 'info',
                'details': open_ports
            })
        high_risk_ports = {
            '21': 'FTP',
            '22': 'SSH',
            '23': 'Telnet',
            '25': 'SMTP',
            '445': 'SMB',
            '3306': 'MySQL',
            '3389': 'RDP',
            '5432': 'PostgreSQL'
        }
        for port_info in open_ports:
            port = str(port_info.get('port'))
            service = port_info.get('service', 'Unknown')
            if port in high_risk_ports:
                findings.append({
                    'title': f'High-Risk Port Open: {port}/{service}',
                    'description': f'The port {port} ({high_risk_ports[port]}) is open and could be a security risk if not properly secured.',
                    'severity': 'high',
                    'recommendation': f'Unless necessary, close port {port} or restrict access to trusted IPs only.'
                })
            else:
                findings.append({
                    'title': f'Open Port: {port}/{service}',
                    'description': f'The port {port} is open running {service}.',
                    'severity': 'medium',
                    'recommendation': 'Ensure this port is necessary for business operations and properly secured.'
                })
        return findings


class WhoisScan(db.Model):
    __tablename__ = 'whois_scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    domain_name = db.Column(db.String(255))
    registrar = db.Column(db.String(255))
    creation_date = db.Column(db.DateTime)
    expiration_date = db.Column(db.DateTime)
    whois_data = db.Column(db.Text)  # Store complete WHOIS data
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def get_findings(self):
        findings = []
        now = datetime.datetime.utcnow()
        if self.expiration_date:
            days_until_expiry = (self.expiration_date - now).days
            if days_until_expiry < 0:
                findings.append({
                    'title': 'Domain Expired',
                    'description': f'The domain has expired {abs(days_until_expiry)} days ago.',
                    'severity': 'critical',
                    'recommendation': 'Renew the domain immediately to prevent domain hijacking.'
                })
            elif days_until_expiry < 30:
                findings.append({
                    'title': 'Domain Expiring Soon',
                    'description': f'The domain will expire in {days_until_expiry} days.',
                    'severity': 'high',
                    'recommendation': 'Renew the domain soon to prevent potential loss or hijacking.'
                })
        findings.append({
            'title': 'WHOIS Information',
            'description': f'Domain: {self.domain_name}, Registrar: {self.registrar}, ' +
                          f'Created: {self.creation_date}, Expires: {self.expiration_date}',
            'severity': 'info'
        })
        return findings


class CookieScan(db.Model):
    __tablename__ = 'cookie_scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    cookies = db.Column(db.Text)  # Store JSON array of cookies
    issues = db.Column(db.Text)  # Store JSON array of cookie issues
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def get_findings(self):
        findings = []
        if not self.cookies:
            findings.append({
                'title': 'No Cookies Detected',
                'description': 'No cookies were detected on the target website.',
                'severity': 'info'
            })
            return findings
        if self.issues:
            cookie_issues = json.loads(self.issues)
            for issue in cookie_issues:
                findings.append({
                    'title': issue.get('title', 'Cookie Security Issue'),
                    'description': issue.get('description', 'A cookie security issue was detected.'),
                    'severity': issue.get('severity', 'medium'),
                    'recommendation': issue.get('recommendation', 'Review and correct cookie configuration.')
                })
        return findings


class TechScan(db.Model):
    """Technology stack scan results"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    technologies = db.Column(db.JSON)
    def get_findings(self):
        findings = []
        if self.technologies:
            findings.append({
                'title': 'Technology Stack Information',
                'description': 'Detected technologies and frameworks',
                'severity': 'info',
                'component': 'Technology Analysis',
                'details': self.technologies
            })
        return findings


class DisclosureScan(db.Model):
    __tablename__ = 'disclosure_scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    credentials_found = db.Column(db.Text)  # Store JSON array of potential credentials
    pii_found = db.Column(db.Text)  # Store JSON array of potential PII
    internal_info_found = db.Column(db.Text)  # Store JSON array of internal info
    url_secrets_found = db.Column(db.Text)  # Store JSON array of secrets in URLs
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def get_findings(self):
        findings = []
        if self.credentials_found:
            creds = json.loads(self.credentials_found)
            for cred in creds:
                cred_type = cred.get("type", "credential")
                context = cred.get("context", "N/A")
                location = cred.get("location", "page")
                cred_type_titles = {
                    "api_key": "API Key",
                    "auth_token": "Authentication Token",
                    "password": "Password",
                    "access_key": "Access Key",
                    "client_secret": "Client Secret",
                    "private_key": "Private Key"
                }
                title = cred_type_titles.get(cred_type, "Authentication Credential")
                findings.append({
                    'title': f'Exposed {title}',
                    'description': f'Found {cred_type} in {location}',
                    'details': f'Finding Information: {context}',
                    'severity': 'critical',
                    'recommendation': 'Remove exposed credentials immediately and rotate any exposed secrets.'
                })
        if self.pii_found:
            pii = json.loads(self.pii_found)
            for item in pii:
                pii_type = item.get("type", "PII")
                context = item.get("context", "N/A")
                location = item.get("location", "page")
                pii_type_titles = {
                    "email": "Email Address",
                    "phone": "Phone Number",
                    "ssn": "Social Security Number",
                    "credit_card": "Credit Card Number",
                    "address": "Physical Address"
                }
                title = pii_type_titles.get(pii_type, "Personal Information")
                severity = 'high' if pii_type in ['password', 'api_key', 'auth_token', 'access_key', 'client_secret', 'private_key'] else 'medium'
                findings.append({
                    'title': f'Exposed {title} (PII)',
                    'description': f'Found {pii_type} in {location}',
                    'details': f'Finding Information: {context}',
                    'severity': severity,
                    'recommendation': 'Remove or protect exposed personal information.'
                })
        if self.internal_info_found:
            internal = json.loads(self.internal_info_found)
            for item in internal:
                info_type = item.get("type", "internal information")
                context = item.get("context", "N/A")
                location = item.get("location", "page")
                info_type_titles = {
                    "internal_ip": "Internal IP Address",
                    "debug_info": "Debug Information",
                    "server_path": "Server File Path",
                    "database_info": "Database Connection String"
                }
                title = info_type_titles.get(info_type, "Internal Information")
                findings.append({
                    'title': f'Exposed {title}',
                    'description': f'Found {info_type} in {location}',
                    'details': f'Finding Information: {context}',
                    'severity': 'medium',
                    'recommendation': 'Remove or obfuscate internal system information.'
                })
        if self.url_secrets_found:
            url_secrets = json.loads(self.url_secrets_found)
            for secret in url_secrets:
                secret_type = secret.get("type", "secret")
                parameter = secret.get("parameter", "unknown")
                url = secret.get("url", "")
                masked_value = secret.get("masked_value", "***")
                secret_type_titles = {
                    "api_key": "API Key",
                    "token": "Authentication Token",
                    "password": "Password",
                    "access_key": "Access Key"
                }
                title = secret_type_titles.get(secret_type, "Secret Parameter")
                findings.append({
                    'title': f'{title} Exposed in URL',
                    'description': f'Found {secret_type} parameter "{parameter}" in URL',
                    'details': f'Finding Information: {url} (value partially masked: {masked_value})',
                    'severity': 'high',
                    'recommendation': 'Avoid passing sensitive information in URLs. Use POST requests with proper encryption instead.'
                })
        return findings


class VisitedUrl(db.Model):
    __tablename__ = 'visited_urls'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    url = db.Column(db.String(1024))
    status_code = db.Column(db.Integer)
    content_type = db.Column(db.String(100))
    visited_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)