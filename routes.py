from flask import render_template, request, redirect, url_for, flash, jsonify, session, abort, Response, send_file
from sqlalchemy import text
from app import app, db
from models import Scan, User
from forms import ScanForm
from scanner import perform_scan, get_scan_progress
import logging
import json
import csv
import io
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

@app.route('/')
def index():
    """Landing page with scan form"""
    form = ScanForm()
    return render_template('index.html', form=form)

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    form = ScanForm()

    if form.validate_on_submit():
        target_url = form.target_url.data

        # Create new scan record
        scan = Scan(
            target_url=target_url,
            is_complete=False
        )
        db.session.add(scan)
        db.session.commit()

        # Start the scan in background
        perform_scan(scan.id)

        # Redirect to scan progress page
        return redirect(url_for('scan_progress', scan_id=scan.id))

    # If form validation failed
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{field}: {error}", "danger")

    return redirect(url_for('index'))

@app.route('/scan/<int:scan_id>/progress')
def scan_progress(scan_id):
    """Show scan progress page"""
    scan = Scan.query.get_or_404(scan_id)
    findings = []

    # Also collect findings for in-progress scans to show partial results
    if scan.is_complete:
        scan_components = [
            scan.ip_scan, scan.dns_scan, scan.ssl_scan, scan.http_scan,
            scan.port_scan, scan.whois_scan, scan.cookie_scan,
            scan.disclosure_scan
        ]

        logging.debug(f"Processing {len([c for c in scan_components if c])} scan components for scan {scan_id}")

        for component in scan_components:
            if component:
                component_findings = component.get_findings()
                logging.debug(f"Got {len(component_findings)} findings from {component.__class__.__name__}")
                findings.extend(component_findings)

        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))

    from datetime import datetime
    return render_template('scan_result.html', scan=scan, is_complete=scan.is_complete, findings=findings, now=datetime.now())

@app.route('/api/scan/<int:scan_id>/progress')
def scan_progress_api(scan_id):
    """API endpoint to get scan progress"""
    progress = get_scan_progress(scan_id)
    return jsonify(progress)

@app.route('/scan/<int:scan_id>/result')
def scan_result(scan_id):
    """Show scan results page"""
    scan = Scan.query.get_or_404(scan_id)

    if not scan.is_complete:
        flash("Scan is still in progress", "warning")
        return redirect(url_for('scan_progress', scan_id=scan_id))

    # Collect findings from all scan components
    findings = []
    scan_components = [
        scan.ip_scan, scan.dns_scan, scan.ssl_scan, scan.http_scan,
        scan.port_scan, scan.whois_scan, scan.cookie_scan,
        scan.disclosure_scan
    ]

    logging.debug(f"Processing {len([c for c in scan_components if c])} scan components for scan {scan_id}")

    for component in scan_components:
        if component:
            component_findings = component.get_findings()
            logging.debug(f"Got {len(component_findings)} findings from {component.__class__.__name__}")
            findings.extend(component_findings)

    # Sort findings by severity
    severity_order = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3,
        'info': 4
    }

    findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))

    logging.debug(f"Total findings for scan {scan_id}: {len(findings)}")
    for i, finding in enumerate(findings):
        logging.debug(f"Finding {i+1}: {finding.get('title')} - {finding.get('severity')}")

    from datetime import datetime
    return render_template('scan_result.html', scan=scan, findings=findings, is_complete=True, now=datetime.now())

@app.route('/dashboard')
def dashboard():
    """Show dashboard with scan statistics"""
    # Get recent scans
    recent_scans = Scan.query.order_by(Scan.scan_date.desc()).limit(10).all()

    # Count vulnerabilities by severity across all scans
    vulnerability_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }

    # Get vulnerability trends data (last 7 days)
    from datetime import datetime, timedelta
    seven_days_ago = datetime.now() - timedelta(days=7)
    trend_scans = Scan.query.filter(Scan.scan_date >= seven_days_ago).order_by(Scan.scan_date).all()

    # Initialize trends data structure
    trends_data = {
        'dates': [],
        'critical': [],
        'high': [],
        'medium': []
    }

    # Group scans by date
    date_grouped_scans = {}
    for scan in trend_scans:
        scan_date = scan.scan_date.strftime('%b %d')
        if scan_date not in date_grouped_scans:
            date_grouped_scans[scan_date] = {
                'critical': 0,
                'high': 0,
                'medium': 0
            }
        date_grouped_scans[scan_date]['critical'] += scan.critical_count
        date_grouped_scans[scan_date]['high'] += scan.high_count
        date_grouped_scans[scan_date]['medium'] += scan.medium_count

    # Fill in any missing dates in the last 7 days
    for i in range(7):
        date = (datetime.now() - timedelta(days=i)).strftime('%b %d')
        if date not in date_grouped_scans:
            date_grouped_scans[date] = {'critical': 0, 'high': 0, 'medium': 0}

    # Sort dates and populate trends data
    sorted_dates = sorted(date_grouped_scans.keys(), 
                        key=lambda x: datetime.strptime(x, '%b %d'))

    trends_data['dates'] = sorted_dates
    for date in sorted_dates:
        trends_data['critical'].append(date_grouped_scans[date]['critical'])
        trends_data['high'].append(date_grouped_scans[date]['high'])
        trends_data['medium'].append(date_grouped_scans[date]['medium'])

    # Common security issues data with detailed counting
    security_issues = {
        'Missing Security Headers': 0,
        'SSL Certificate Issues': 0,
        'Exposed Sensitive Info': 0,
        'Open Ports': 0,
        'CORS Misconfigurations': 0
    }

    for scan in recent_scans:
        # Update total counts
        vulnerability_counts['critical'] += scan.critical_count
        vulnerability_counts['high'] += scan.high_count
        vulnerability_counts['medium'] += scan.medium_count
        vulnerability_counts['low'] += scan.low_count
        vulnerability_counts['info'] += scan.info_count

        # Count actual security issues from scan results
        if scan.http_scan:
            if scan.http_scan.missing_headers:
                missing_headers = json.loads(scan.http_scan.missing_headers or '[]')
                security_issues['Missing Security Headers'] += len(missing_headers)

        if scan.ssl_scan:
            if scan.ssl_scan.issues:
                ssl_issues = json.loads(scan.ssl_scan.issues or '[]')
                security_issues['SSL Certificate Issues'] += len(ssl_issues)

        if scan.disclosure_scan:
            sensitive_count = 0
            if scan.disclosure_scan.credentials_found:
                credentials = json.loads(scan.disclosure_scan.credentials_found or '[]')
                sensitive_count += len(credentials)
            if scan.disclosure_scan.pii_found:
                pii = json.loads(scan.disclosure_scan.pii_found or '[]')
                sensitive_count += len(pii)
            security_issues['Exposed Sensitive Info'] += sensitive_count

        if scan.port_scan and scan.port_scan.open_ports:
            ports = json.loads(scan.port_scan.open_ports or '[]')
            security_issues['Open Ports'] += len(ports)

        # CORS scan removed

    # Prepare trends data
    for scan in trend_scans:
        scan_date = scan.scan_date.strftime('%b %d')
        if scan_date not in trends_data['dates']:
            trends_data['dates'].append(scan_date)
            trends_data['critical'].append(scan.critical_count)
            trends_data['high'].append(scan.high_count)
            trends_data['medium'].append(scan.medium_count)

    return render_template('dashboard.html', 
                         recent_scans=recent_scans, 
                         vulnerability_counts=vulnerability_counts,
                         trends_data=trends_data,
                         security_issues=security_issues)

@app.route('/history')
def scan_history():
    """Show scan history"""
    scans = Scan.query.order_by(Scan.scan_date.desc()).all()
    return render_template('history.html', scans=scans)

@app.route('/scan/<int:scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    """Delete a scan and all related data"""
    scan = Scan.query.get_or_404(scan_id)

    try:
        # First, delete any related entries in the cors_scans table
        db.session.execute(text('DELETE FROM cors_scans WHERE scan_id = :scan_id'), {'scan_id': scan_id})
        
        # Now delete the scan itself
        db.session.delete(scan)
        db.session.commit()
        flash('Scan deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting scan: {str(e)}', 'danger')
        logging.error(f"Error deleting scan {scan_id}: {str(e)}")

    return redirect(url_for('scan_history'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logging.error(f"Server error: {e}")
    return render_template('500.html'), 500

@app.route('/scan/<int:scan_id>/export/<format>')
def export_scan_report(scan_id, format):
    """Export scan report in different formats (PDF, JSON, CSV)"""
    scan = Scan.query.get_or_404(scan_id)

    if not scan.is_complete:
        flash("Cannot export report for an incomplete scan", "warning")
        return redirect(url_for('scan_progress', scan_id=scan_id))

    # Collect findings from all scan components
    findings = []
    scan_components = [
        scan.ip_scan, scan.dns_scan, scan.ssl_scan, scan.http_scan,
        scan.port_scan, scan.whois_scan, scan.cookie_scan,
        scan.disclosure_scan
    ]

    for component in scan_components:
        if component:
            component_findings = component.get_findings()
            findings.extend(component_findings)

    # Sort findings by severity
    severity_order = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3,
        'info': 4
    }

    findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))

    # Generate report based on the requested format
    if format.lower() == 'pdf':
        return create_pdf_report(scan, findings)
    elif format.lower() == 'json':
        return create_json_report(scan, findings)
    elif format.lower() == 'csv':
        return create_csv_report(scan, findings)
    else:
        flash(f"Unsupported export format: {format}", "danger")
        return redirect(url_for('scan_result', scan_id=scan_id))

def create_pdf_report(scan, findings):
    """Create a PDF report of scan findings"""
    buffer = io.BytesIO()

    # Create the PDF document
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()

    # Add custom styles
    custom_title_style = ParagraphStyle(name='CustomTitle', 
                             parent=styles['Heading1'], 
                             fontName='Helvetica-Bold',
                             fontSize=16,
                             spaceAfter=16)

    custom_heading_style = ParagraphStyle(name='CustomHeading', 
                             parent=styles['Heading2'], 
                             fontName='Helvetica-Bold',
                             fontSize=14,
                             spaceAfter=10)

    custom_normal_style = ParagraphStyle(name='CustomNormal', 
                             parent=styles['Normal'], 
                             fontName='Helvetica',
                             fontSize=10)

    # Initialize story elements
    elements = []

    # Add report title
    elements.append(Paragraph(f"Security Scan Report: {scan.target_url}", custom_title_style))
    elements.append(Spacer(1, 0.25 * inch))

    # Add scan details
    elements.append(Paragraph("Scan Details:", custom_heading_style))
    scan_date = scan.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')
    elements.append(Paragraph(f"<b>Target URL:</b> {scan.target_url}", custom_normal_style))
    elements.append(Paragraph(f"<b>Scan Date:</b> {scan_date}", custom_normal_style))
    elements.append(Spacer(1, 0.25 * inch))

    # Add vulnerability summary
    elements.append(Paragraph("Vulnerability Summary:", custom_heading_style))
    summary_data = [
        ["Severity", "Count"],
        ["Critical", str(scan.critical_count)],
        ["High", str(scan.high_count)],
        ["Medium", str(scan.medium_count)],
        ["Low", str(scan.low_count)],
        ["Info", str(scan.info_count)]
    ]

    summary_table = Table(summary_data, colWidths=[2 * inch, 1 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (1, 0), 12),
        ('BACKGROUND', (0, 1), (0, 1), colors.darkred),
        ('BACKGROUND', (0, 2), (0, 2), colors.orange),
        ('BACKGROUND', (0, 3), (0, 3), colors.blue),
        ('BACKGROUND', (0, 4), (0, 4), colors.lightblue),
        ('BACKGROUND', (0, 5), (0, 5), colors.grey),
        ('TEXTCOLOR', (0, 1), (0, 5), colors.whitesmoke),
        ('GRID', (0, 0), (1, 5), 1, colors.black),
        ('ALIGN', (1, 1), (1, 5), 'CENTER'),
        ('VALIGN', (0, 0), (1, 5), 'MIDDLE')
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 0.25 * inch))

    # Add DNS Information
    if scan.dns_scan:
        elements.append(Paragraph("DNS Information:", custom_heading_style))
        elements.append(Spacer(1, 0.15 * inch))
        dns_records = json.loads(scan.dns_scan.dns_records or '{}')
        nameservers = json.loads(scan.dns_scan.nameservers or '[]')

        for record_type, records in dns_records.items():
            elements.append(Paragraph(f"<b>{record_type} Records:</b>", custom_normal_style))
            for record in records:
                elements.append(Paragraph(f"• {record}", custom_normal_style))
            elements.append(Spacer(1, 0.1 * inch))

        elements.append(Paragraph("<b>Nameservers:</b>", custom_normal_style))
        for ns in nameservers:
            elements.append(Paragraph(f"• {ns}", custom_normal_style))
        elements.append(Spacer(1, 0.25 * inch))

    # Add SSL Certificate Information
    if scan.ssl_scan:
        elements.append(Paragraph("SSL Certificate Information:", custom_heading_style))
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph(f"<b>Issuer:</b> {scan.ssl_scan.cert_issuer}", custom_normal_style))
        elements.append(Paragraph(f"<b>Subject:</b> {scan.ssl_scan.cert_subject}", custom_normal_style))
        elements.append(Paragraph(f"<b>Valid From:</b> {scan.ssl_scan.valid_from}", custom_normal_style))
        elements.append(Paragraph(f"<b>Valid Until:</b> {scan.ssl_scan.valid_until}", custom_normal_style))
        elements.append(Paragraph(f"<b>Version:</b> {scan.ssl_scan.certificate_version}", custom_normal_style))
        elements.append(Spacer(1, 0.25 * inch))

    # Add HTTPS Information
    if scan.http_scan:
        elements.append(Paragraph("HTTPS Configuration:", custom_heading_style))
        elements.append(Spacer(1, 0.15 * inch))
        if scan.http_scan.redirect_to_https:
            elements.append(Paragraph("✓ HTTP to HTTPS redirection is properly configured", custom_normal_style))
        else:
            elements.append(Paragraph("✗ HTTP to HTTPS redirection is not configured", custom_normal_style))
        elements.append(Spacer(1, 0.25 * inch))

    # Add HTTP Headers
    if scan.http_scan and scan.http_scan.headers:
        elements.append(Paragraph("HTTP Headers:", custom_heading_style))
        elements.append(Spacer(1, 0.15 * inch))
        headers = json.loads(scan.http_scan.headers)
        for header, value in headers.items():
            elements.append(Paragraph(f"<b>{header}:</b> {value}", custom_normal_style))
        elements.append(Spacer(1, 0.25 * inch))

    # Add WHOIS Information
    if scan.whois_scan:
        elements.append(Paragraph("WHOIS Information:", custom_heading_style))
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph(f"<b>Domain Name:</b> {scan.whois_scan.domain_name}", custom_normal_style))
        elements.append(Paragraph(f"<b>Registrar:</b> {scan.whois_scan.registrar}", custom_normal_style))
        elements.append(Paragraph(f"<b>Creation Date:</b> {scan.whois_scan.creation_date}", custom_normal_style))
        elements.append(Paragraph(f"<b>Expiration Date:</b> {scan.whois_scan.expiration_date}", custom_normal_style))
        elements.append(Spacer(1, 0.25 * inch))

    # Add Ports & Services
    if scan.port_scan and scan.port_scan.open_ports:
        elements.append(Paragraph("Open Ports & Services:", custom_heading_style))
        elements.append(Spacer(1, 0.15 * inch))
        open_ports = json.loads(scan.port_scan.open_ports)
        for port_info in open_ports:
            elements.append(Paragraph(f"<b>Port {port_info['port']}:</b> {port_info.get('service', 'Unknown')} ({port_info.get('state', 'Unknown')})", custom_normal_style))
        elements.append(Spacer(1, 0.25 * inch))


    # Add CSP Information
    if scan.http_scan and scan.http_scan.csp_issues:
        elements.append(Paragraph("Content Security Policy:", custom_heading_style))
        elements.append(Spacer(1, 0.15 * inch))
        csp_issues = json.loads(scan.http_scan.csp_issues)
        for issue in csp_issues:
            elements.append(Paragraph(f"<b>{issue['name']}</b>", custom_normal_style))
            elements.append(Paragraph(f"Description: {issue['description']}", custom_normal_style))
            elements.append(Paragraph(f"Recommendation: {issue['recommendation']}", custom_normal_style))
            elements.append(Spacer(1, 0.1 * inch))
        elements.append(Spacer(1, 0.25 * inch))

    # Add detailed findings
    elements.append(Paragraph("Detailed Findings:", custom_heading_style))
    if findings:
        for i, finding in enumerate(findings):
            # Add severity indicator
            severity = finding.get('severity', 'info').lower()
            severity_color = {
                'critical': colors.darkred,
                'high': colors.orange,
                'medium': colors.blue,
                'low': colors.lightblue,
                'info': colors.grey
            }.get(severity, colors.grey)

            # Create a severity indicator table
            severity_table = Table([[severity.upper()]], colWidths=[1 * inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), severity_color),
                ('TEXTCOLOR', (0, 0), (0, 0), colors.whitesmoke),
                ('ALIGNMENT', (0, 0), (0, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (0, 0), 10),
                ('BOTTOMPADDING', (0, 0), (0, 0), 6),
                ('TOPPADDING', (0, 0), (0, 0), 6),
            ]))

            elements.append(severity_table)
            elements.append(Spacer(1, 0.1 * inch))

            # Finding title
            elements.append(Paragraph(f"<b>{finding.get('title', 'Unknown Issue')}</b>", custom_normal_style))

            # Finding description
            if 'description' in finding:
                elements.append(Paragraph(f"<b>Description:</b> {finding.get('description')}", custom_normal_style))

            # Finding recommendation
            if 'recommendation' in finding:
                elements.append(Paragraph(f"<b>Recommendation:</b> {finding.get('recommendation')}", custom_normal_style))

            # Finding component
            if 'component' in finding:
                elements.append(Paragraph(f"<b>Component:</b> {finding.get('component')}", custom_normal_style))

            elements.append(Spacer(1, 0.15 * inch))
    else:
        elements.append(Paragraph("No findings to report.", custom_normal_style))

    # Build the PDF document
    doc.build(elements)

    # Set up the response
    buffer.seek(0)
    scan_date_for_filename = scan.scan_date.strftime('%Y%m%d_%H%M%S')
    target_for_filename = scan.target_url.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"security_scan_{target_for_filename}_{scan_date_for_filename}.pdf",
        mimetype='application/pdf'
    )

def create_json_report(scan, findings):
    """Create a JSON report of scan findings"""
    # Convert scan data to a more json-friendly structure
    scan_date = scan.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')

    # Create report structure
    report_data = {
        'scan_id': scan.id,
        'target_url': scan.target_url,
        'scan_date': scan_date,
        'vulnerability_summary': {
            'critical': scan.critical_count,
            'high': scan.high_count,
            'medium': scan.medium_count,
            'low': scan.low_count,
            'info': scan.info_count,
            'total': scan.critical_count + scan.high_count + scan.medium_count + scan.low_count + scan.info_count
        },
        'findings': findings
    }

    # Format the JSON
    formatted_json = json.dumps(report_data, indent=4)

    # Generate the filename
    scan_date_for_filename = scan.scan_date.strftime('%Y%m%d_%H%M%S')
    target_for_filename = scan.target_url.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')
    filename = f"security_scan_{target_for_filename}_{scan_date_for_filename}.json"

    # Create response
    response = Response(
        formatted_json,
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename={filename}'
        }
    )

    return response

def create_csv_report(scan, findings):
    """Create a CSV report of scan findings"""
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        'Severity', 'Title', 'Description', 'Recommendation', 'Component', 'Scan Date', 'Target URL'
    ])

    # Write scan data rows
    scan_date = scan.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')

    if findings:
        for finding in findings:
            writer.writerow([
                finding.get('severity', 'Unknown'),
                finding.get('title', 'Unknown Issue'),
                finding.get('description', ''),
                finding.get('recommendation', ''),
                finding.get('component', ''),
                scan_date,
                scan.target_url
            ])
    else:
        writer.writerow(['Info', 'No findings', 'No security issues were found', '', '', scan_date, scan.target_url])

    # Reset the io position and create the response
    output.seek(0)

    # Generate the filename
    scan_date_for_filename = scan.scan_date.strftime('%Y%m%d_%H%M%S')
    target_for_filename = scan.target_url.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')
    filename = f"security_scan_{target_for_filename}_{scan_date_for_filename}.csv"

    # Create response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename={filename}'
        }
    )