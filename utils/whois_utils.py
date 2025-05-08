import json
import whois
import logging
from urllib.parse import urlparse

def scan_whois(url):
    """
    Get WHOIS information for a domain
    
    Args:
        url (str): The URL to scan
        
    Returns:
        dict: Dictionary containing WHOIS information
    """
    result = {
        'domain_name': None,
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'whois_data': None
    }
    
    try:
        # Extract domain from URL
        parsed_url = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
        domain = parsed_url.netloc or parsed_url.path
        if ':' in domain:  # Remove port if present
            domain = domain.split(':')[0]
        
        if not domain:
            logging.error("Invalid domain name")
            return result
            
        # Get WHOIS information
        whois_info = whois.whois(domain)
        
        if not whois_info or not any(whois_info.values()):
            logging.error(f"No WHOIS data found for domain: {domain}")
            return result
        
        # Store domain name
        if whois_info.domain_name:
            # Handle case where domain_name is a list
            if isinstance(whois_info.domain_name, list):
                result['domain_name'] = whois_info.domain_name[0]
            else:
                result['domain_name'] = whois_info.domain_name
        
        # Store registrar
        if whois_info.registrar:
            result['registrar'] = whois_info.registrar
        
        # Store creation date
        if whois_info.creation_date:
            # Handle case where creation_date is a list
            if isinstance(whois_info.creation_date, list):
                result['creation_date'] = whois_info.creation_date[0]
            else:
                result['creation_date'] = whois_info.creation_date
        
        # Store expiration date
        if whois_info.expiration_date:
            # Handle case where expiration_date is a list
            if isinstance(whois_info.expiration_date, list):
                result['expiration_date'] = whois_info.expiration_date[0]
            else:
                result['expiration_date'] = whois_info.expiration_date
        
        # Store complete WHOIS data as JSON
        try:
            # Convert the object to a dictionary and filter out non-serializable items
            whois_dict = {}
            for key, value in whois_info.items():
                # Skip non-serializable values or convert them to strings
                if key != 'status':  # status can be a set which is not serializable
                    if isinstance(value, (str, int, float, bool, list, dict, tuple, type(None))):
                        whois_dict[key] = value
                    else:
                        whois_dict[key] = str(value)
                else:
                    # Handle status field (can be a set)
                    if isinstance(value, set):
                        whois_dict[key] = list(value)
                    else:
                        whois_dict[key] = value
            
            result['whois_data'] = json.dumps(whois_dict)
        except Exception as e:
            logging.error(f"Error converting WHOIS data to JSON: {str(e)}")
            result['whois_data'] = json.dumps({"error": "Could not serialize complete WHOIS data"})
    
    except whois.parser.PywhoisError as e:
        logging.error(f"WHOIS parsing error: {str(e)}")
    except Exception as e:
        logging.error(f"Error in scan_whois: {str(e)}")
    
    return result
