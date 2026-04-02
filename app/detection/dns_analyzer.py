import dns.resolver
from urllib.parse import urlparse

def analyze_dns(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        if ':' in domain:
            domain = domain.split(':')[0]
        
        result = {
            'domain': domain,
            'has_spf': False,
            'has_dkim': False,
            'has_dmarc': False,
            'spf_record': None,
            'dkim_record': None,
            'dmarc_record': None
        }
        
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            for record in spf_records:
                if 'v=spf1' in str(record):
                    result['has_spf'] = True
                    result['spf_record'] = str(record)
        except:
            pass
        
        try:
            dkim_selector = 'default'
            dkim_domain = f'{dkim_selector}._domainkey.{domain}'
            dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
            for record in dkim_records:
                if 'v=DKIM1' in str(record):
                    result['has_dkim'] = True
                    result['dkim_record'] = str(record)
        except:
            pass
        
        try:
            dmarc_domain = f'_dmarc.{domain}'
            dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            for record in dmarc_records:
                if 'v=DMARC1' in str(record):
                    result['has_dmarc'] = True
                    result['dmarc_record'] = str(record)
        except:
            pass
        
        return result
    
    except Exception as e:
        return {'error': str(e)}

def get_whois_info(domain):
    try:
        import whois
        w = whois.whois(domain)
        
        return {
            'domain_name': w.domain_name,
            'registrar': w.registrar,
            'creation_date': str(w.creation_date),
            'expiration_date': str(w.expiration_date),
            'name_servers': w.name_servers,
            'status': w.status
        }
    except Exception as e:
        return {'error': str(e)}