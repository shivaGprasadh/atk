
import subprocess
import json
import logging
from pathlib import Path

def scan_cors(target_url):
    """Scan target for CORS misconfigurations using Corsy"""
    try:
        corsy_path = Path('Corsy/corsy.py')
        if not corsy_path.exists():
            logging.error("Corsy scanner not found")
            return []

        # Run Corsy with the target URL
        command = ['python3', str(corsy_path), '-u', target_url]
        result = subprocess.run(command, 
                              capture_output=True, 
                              text=True,
                              cwd='.')
        
        findings = []
        
        # Parse Corsy output
        if result.stdout:
            output = result.stdout
            if 'ＣＯＲＳＹ' in output:
                finding = {}
                lines = output.split('\n')
                current_url = None
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('http'):
                        if finding and 'class' in finding:
                            findings.append(finding.copy())
                        current_url = line
                        finding = {'url': current_url}
                    elif line.startswith('- Class:'):
                        finding['class'] = line.split(':', 1)[1].strip()
                    elif line.startswith('- Description:'):
                        finding['description'] = line.split(':', 1)[1].strip() 
                    elif line.startswith('- Severity:'):
                        finding['severity'] = line.split(':', 1)[1].strip()
                    elif line.startswith('- Exploitation:'):
                        finding['exploitation'] = line.split(':', 1)[1].strip()
                    elif line.startswith('- ACAO Header:'):
                        finding['acao_header'] = line.split(':', 1)[1].strip()
                    elif line.startswith('- ACAC Header:'):
                        finding['acac_header'] = line.split(':', 1)[1].strip()
                
                if finding and 'class' in finding:
                    findings.append(finding.copy())
                output = result.stdout
                if 'ＣＯＲＳＹ' in output:
                    finding = {}
                    lines = output.split('\n')
                    current_url = None
                    
                    for line in lines:
                        line = line.strip()
                        if line.startswith('http'):
                            current_url = line
                            finding = {'url': current_url}
                        elif line.startswith('- Class:'):
                            finding['class'] = line.split(':', 1)[1].strip()
                        elif line.startswith('- Description:'):
                            finding['description'] = line.split(':', 1)[1].strip()
                        elif line.startswith('- Severity:'):
                            finding['severity'] = line.split(':', 1)[1].strip()
                        elif line.startswith('- Exploitation:'):
                            finding['exploitation'] = line.split(':', 1)[1].strip()
                        elif line.startswith('- ACAO Header:'):
                            finding['acao_header'] = line.split(':', 1)[1].strip()
                        elif line.startswith('- ACAC Header:'):
                            finding['acac_header'] = line.split(':', 1)[1].strip()
                            if finding:
                                findings.append(finding.copy())
                                finding = {'url': current_url} if current_url else {}

        return findings
    except Exception as e:
        logging.error(f"Error running Corsy: {str(e)}")
        return []
