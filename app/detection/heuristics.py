import math
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs
import requests
from bs4 import BeautifulSoup

def shannon_entropy(text):
    if not text:
        return 0
    counter = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def calculate_url_length_score(url):
    length = len(url)
    if length < 50:
        return 0.1
    elif length < 100:
        return 0.3
    elif length < 200:
        return 0.5
    elif length < 500:
        return 0.7
    return 0.9

def calculate_special_char_score(url):
    special_chars = ['@', '#', '$', '%', '^', '&', '*', '!', '~', '`', '|', '\\', '/', ':', ';', '"', "'"]
    count = sum(url.count(c) for c in special_chars)
    return min(count / 10, 1.0)

def calculate_encoded_char_score(url):
    encoded = url.count('%')
    return min(encoded / 5, 1.0)

def calculate_subdomain_count_score(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    subdomains = domain.split('.')
    if len(subdomains) > 3:
        return 0.8
    elif len(subdomains) > 2:
        return 0.5
    return 0.1

def calculate_ip_address_score(url):
    parsed = urlparse(url)
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, parsed.netloc):
        return 0.9
    return 0.0

def calculate_suspicious_tld_score(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    tlds = ['.xyz', '.top', '.gq', '.cf', '.tk', '.ml', '.ga', '.work', '.click', '.link', '.pw', '.cc', '.ws', '.info', '.biz']
    for tld in tlds:
        if domain.endswith(tld):
            return 0.8
    return 0.0

def calculate_entropy_score(url):
    entropy = shannon_entropy(url)
    if entropy > 4.5:
        return 0.9
    elif entropy > 4.0:
        return 0.7
    elif entropy > 3.5:
        return 0.5
    elif entropy > 3.0:
        return 0.3
    return 0.1

def calculate_login_form_score(html_content):
    if not html_content:
        return 0.0
    
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = soup.find_all('form')
    login_indicators = ['login', 'signin', 'password', 'username', 'email', 'credential']
    
    for form in forms:
        form_text = str(form).lower()
        if any(indicator in form_text for indicator in login_indicators):
            return 0.8
    
    return 0.0

def calculate_hidden_elements_score(html_content):
    if not html_content:
        return 0.0
    
    soup = BeautifulSoup(html_content, 'html.parser')
    hidden_elements = soup.find_all(style=lambda x: x and 'display:none' in x)
    hidden_elements += soup.find_all(style=lambda x: x and 'visibility:hidden' in x)
    hidden_elements += soup.find_all(class_=lambda x: x and 'hidden' in x)
    
    return min(len(hidden_elements) / 5, 1.0)

def calculate_brand_impersonation_score(url, html_content):
    brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'bank', 'chase', 'wellsfargo', 'bankofamerica']
    url_lower = url.lower()
    
    brand_count = sum(1 for brand in brands if brand in url_lower)
    
    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        title = soup.find('title')
        if title:
            title_text = title.text.lower()
            brand_count += sum(1 for brand in brands if brand in title_text)
    
    return min(brand_count * 0.2, 1.0)

def calculate_urgency_words_score(html_content):
    if not html_content:
        return 0.0
    
    urgency_words = [
        'urgent', 'immediately', 'action required', 'verify your account', 
        'suspended', 'locked', 'unauthorized', 'compromised', 'expire',
        '24 hours', '48 hours', 'limited time', 'act now', 'last chance'
    ]
    
    content_lower = html_content.lower()
    count = sum(1 for word in urgency_words if word in content_lower)
    
    return min(count * 0.15, 1.0)

def calculate_redirect_count_score(url):
    try:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})
        response = session.get(url, allow_redirects=True, timeout=10)
        redirect_count = len(response.history)
        
        if redirect_count > 5:
            return 0.9
        elif redirect_count > 3:
            return 0.7
        elif redirect_count > 1:
            return 0.5
        return 0.1
    except:
        return 0.0

def calculate_shortened_url_score(url):
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
    parsed = urlparse(url)
    
    for shortener in shorteners:
        if shortener in parsed.netloc:
            return 0.7
    return 0.0

def calculate_suspicious_words_score(url):
    suspicious_words = [
        'verify', 'secure', 'update', 'confirm', 'account', 'password',
        'login', 'signin', 'banking', 'support', 'help', 'reward',
        'winner', 'prize', 'free', 'gift', 'claim'
    ]
    
    url_lower = url.lower()
    count = sum(1 for word in suspicious_words if word in url_lower)
    
    return min(count * 0.15, 1.0)

def calculate_homoglyph_score(url):
    homoglyphs = {
        'a': ['а', '@', '4'],
        'e': ['3', 'е'],
        'i': ['1', 'l', '|', 'і'],
        'o': ['0', 'о'],
        's': ['$', '5', 'ѕ'],
        't': ['7', '+'],
        'u': ['υ', 'ü'],
        'w': ['ш', 'vv'],
        'b': ['6', 'ƅ'],
    }
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    score = 0
    for char, replacements in homoglyphs.items():
        for replacement in replacements:
            if replacement in domain and replacement != char:
                score += 0.2
    
    return min(score, 1.0)

def analyze_url(url, html_content=None):
    heuristics_results = {}
    
    heuristics_results['url_length'] = calculate_url_length_score(url)
    heuristics_results['special_chars'] = calculate_special_char_score(url)
    heuristics_results['encoded_chars'] = calculate_encoded_char_score(url)
    heuristics_results['subdomain_count'] = calculate_subdomain_count_score(url)
    heuristics_results['ip_address'] = calculate_ip_address_score(url)
    heuristics_results['suspicious_tld'] = calculate_suspicious_tld_score(url)
    heuristics_results['entropy'] = calculate_entropy_score(url)
    heuristics_results['suspicious_words'] = calculate_suspicious_words_score(url)
    heuristics_results['shortened_url'] = calculate_shortened_url_score(url)
    heuristics_results['homoglyph'] = calculate_homoglyph_score(url)
    heuristics_results['redirect_count'] = calculate_redirect_count_score(url)
    
    if html_content:
        heuristics_results['login_form'] = calculate_login_form_score(html_content)
        heuristics_results['hidden_elements'] = calculate_hidden_elements_score(html_content)
        heuristics_results['brand_impersonation'] = calculate_brand_impersonation_score(url, html_content)
        heuristics_results['urgency_words'] = calculate_urgency_words_score(html_content)
    
    total_score = sum(heuristics_results.values()) / len(heuristics_results)
    heuristics_results['total_score'] = total_score
    
    if total_score < 0.3:
        heuristics_results['result'] = 'safe'
    elif total_score < 0.6:
        heuristics_results['result'] = 'suspicious'
    else:
        heuristics_results['result'] = 'phishing'
    
    heuristics_results['confidence'] = min(total_score * 1.2, 1.0)
    
    return heuristics_results