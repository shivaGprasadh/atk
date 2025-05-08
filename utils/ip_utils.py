import socket
import json
import ipaddress
import requests
import logging

def scan_ip(url):
    """
    Get IP information for a given URL
    
    Args:
        url (str): The URL to scan
        
    Returns:
        dict: Dictionary containing IP information
    """
    result = {
        'ip_address': None,
        'hostname': None,
        'geolocation': None,
        'asn_info': None,
        'is_private': False
    }
    
    try:
        # Extract hostname from URL
        hostname = url.replace('http://', '').replace('https://', '').split('/')[0]
        if ':' in hostname:  # Remove port if present
            hostname = hostname.split(':')[0]
        
        # Resolve IP address
        ip_address = socket.gethostbyname(hostname)
        result['ip_address'] = ip_address
        result['hostname'] = hostname
        
        # Check if IP is private
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            result['is_private'] = ip_obj.is_private
        except ValueError:
            logging.error(f"Invalid IP address: {ip_address}")
        
        # Get geolocation and ASN information
        try:
            geo_response = requests.get(f"https://ipinfo.io/{ip_address}/json")
            if geo_response.status_code == 200:
                geo_data = geo_response.json()
                
                # Extract relevant geolocation data
                geolocation = {
                    'city': geo_data.get('city'),
                    'region': geo_data.get('region'),
                    'country': geo_data.get('country'),
                    'location': geo_data.get('loc'),
                    'timezone': geo_data.get('timezone')
                }
                result['geolocation'] = json.dumps(geolocation)
                
                # Extract ASN information
                asn_info = {
                    'asn': geo_data.get('org', '').split()[0] if 'org' in geo_data else None,
                    'organization': ' '.join(geo_data.get('org', '').split()[1:]) if 'org' in geo_data else None
                }
                result['asn_info'] = json.dumps(asn_info)
        except Exception as e:
            logging.error(f"Error getting geolocation data: {str(e)}")
    
    except socket.gaierror:
        logging.error(f"Could not resolve hostname: {url}")
    except Exception as e:
        logging.error(f"Error in scan_ip: {str(e)}")
    
    return result
