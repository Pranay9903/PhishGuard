import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import requests

def get_ssl_info(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        
        issuer = dict(x[0] for x in cert['issuer'])
        issued_to = dict(x[0] for x in cert['subject'])
        
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        days_until_expiry = (not_after - datetime.utcnow()).days
        
        result = {
            'valid': True,
            'issuer': issuer.get('commonName', 'Unknown'),
            'subject': issued_to.get('commonName', 'Unknown'),
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'days_until_expiry': days_until_expiry,
            'self_signed': issuer.get('commonName') == issued_to.get('commonName')
        }
        
        if days_until_expiry < 0:
            result['valid'] = False
            result['issue'] = 'Certificate expired'
        elif days_until_expiry < 30:
            result['valid'] = False
            result['issue'] = 'Certificate expiring soon'
        
        return result
    
    except Exception as e:
        return {
            'valid': False,
            'error': str(e),
            'issuer': None,
            'days_until_expiry': None
        }

def check_certificate_transparency(hostname):
    try:
        url = f"https://crt.sh/?q={hostname}&output=json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            certs = response.json()
            return {
                'certificates_found': len(certs),
                'recent_certs': certs[:5] if certs else []
            }
    except:
        pass
    return {'certificates_found': 0, 'recent_certs': []}