import json
import logging
import nmap
import socket

def scan_ports(ip_address, scan_type='basic'):
    """
    Scan open ports on the target IP
    
    Args:
        ip_address (str): The IP address to scan
        scan_type (str): Type of scan ('basic' or 'full')
        
    Returns:
        dict: Dictionary containing port scanning results
    """
    result = {
        'open_ports': None
    }
    
    if not ip_address:
        return result
    
    try:
        # Check if IP is valid
        socket.inet_aton(ip_address)
        
        # Initialize port scanner
        nm = nmap.PortScanner()
        
        # Define scan parameters based on scan type
        if scan_type == 'full':
            # Scan most common 1000 ports
            arguments = '-sV -T4'
            ports = None  # Default is top 1000 ports
        else:
            # Basic scan of common ports
            arguments = '-sV -T4'
            ports = '21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080'
        
        # Run the scan
        nm.scan(hosts=ip_address, ports=ports, arguments=arguments)
        
        # Process results
        open_ports = []
        
        # Check if IP was scanned successfully
        if ip_address in nm.all_hosts():
            for proto in nm[ip_address].all_protocols():
                lport = sorted(nm[ip_address][proto].keys())
                
                for port in lport:
                    port_info = nm[ip_address][proto][port]
                    
                    # Extract relevant port information
                    port_data = {
                        'port': port,
                        'protocol': proto,
                        'state': port_info['state'],
                        'service': port_info.get('name', 'unknown'),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', '')
                    }
                    
                    open_ports.append(port_data)
        
        if open_ports:
            result['open_ports'] = json.dumps(open_ports)
    
    except socket.error:
        logging.error(f"Invalid IP address: {ip_address}")
    except nmap.PortScannerError as e:
        logging.error(f"Nmap scanning error: {str(e)}")
    except Exception as e:
        logging.error(f"Error in scan_ports: {str(e)}")
    
    return result
