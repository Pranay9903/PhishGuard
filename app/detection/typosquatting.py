from app.detection.heuristics import levenshtein_distance
from urllib.parse import urlparse

TOP_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com',
    'paypal.com', 'netflix.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
    'citi.com', 'usbank.com', 'capitalone.com', 'americanexpress.com', 'discover.com',
    'dropbox.com', 'box.com', 'linkedin.com', 'twitter.com', 'instagram.com',
    'tiktok.com', 'reddit.com', 'youtube.com', 'yahoo.com', 'bing.com',
    'slack.com', 'zoom.us', 'teams.microsoft.com', 'github.com', 'gitlab.com',
    'bitbucket.org', 'stackoverflow.com', 'medium.com', 'wordpress.com', 'shopify.com',
    'walmart.com', 'target.com', 'bestbuy.com', 'homedepot.com', 'lowes.com',
    'costco.com', 'fedex.com', 'ups.com', 'usps.com', 'dhl.com',
    'whatsapp.com', 'telegram.org', 'discord.com', 'spotify.com', 'adobe.com',
    'autodesk.com', 'salesforce.com', 'oracle.com', 'ibm.com', 'intuit.com',
    'etsy.com', 'ebay.com', 'airbnb.com', 'uber.com', 'lyft.com'
]

HOMOGLYPHS = {
    'a': ['а', '@', '4', 'ą', 'α'],
    'b': ['ƅ', '6', 'ƃ'],
    'c': ['ç', 'ć', 'ċ'],
    'd': ['đ', 'ɗ'],
    'e': ['3', 'е', 'ė', 'ę'],
    'g': ['ġ', 'ǵ'],
    'h': ['һ', 'ḥ'],
    'i': ['1', 'l', '|', 'і', 'ı'],
    'j': ['ĵ', 'ј'],
    'k': ['ķ', 'κ'],
    'l': ['1', 'i', '|', 'ł', 'λ'],
    'n': ['ń', 'ñ', 'η'],
    'o': ['0', 'о', 'ø', 'ö'],
    'p': ['ρ', 'þ'],
    's': ['$', '5', 'ѕ', 'ś'],
    't': ['7', '+', 'τ', 'ţ'],
    'u': ['υ', 'ü', 'ų'],
    'w': ['ш', 'vv', 'ŵ'],
    'x': ['χ', '×'],
    'y': ['ý', 'ÿ', 'γ'],
    'z': ['ż', 'ź', 'ž']
}

def detect_typosquatting(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    if ':' in domain:
        domain = domain.split(':')[0]
    
    if 'www.' in domain:
        domain = domain.replace('www.', '')
    
    tld = ''
    if '.' in domain:
        parts = domain.split('.')
        if len(parts) > 1:
            tld = '.' + parts[-1]
            domain = '.'.join(parts[:-1])
    
    results = []
    
    for top_domain in TOP_DOMAINS:
        top = top_domain.replace('www.', '')
        top_name = top.split('.')[0]
        
        distance = levenshtein_distance(domain, top_name)
        
        if distance > 0 and distance <= 3:
            results.append({
                'typo_domain': top_domain,
                'distance': distance,
                'type': 'typosquatting'
            })
        
        for char, homoglyphs in HOMOGLYPHS.items():
            for homoglyph in homoglyphs:
                if homoglyph in domain and char != domain[domain.index(homoglyph):domain.index(homoglyph)+1]:
                    results.append({
                        'typo_domain': domain + tld,
                        'homoglyph': homoglyph,
                        'original': char,
                        'type': 'homoglyph'
                    })
    
    return results[:10]