from langdetect import detect, LangDetectException
from bs4 import BeautifulSoup

URGENCY_PATTERNS = {
    'en': ['urgent', 'immediately', 'action required', 'verify your account', 'suspended', 'locked', 'unauthorized', 'compromised', 'expire', '24 hours', '48 hours', 'limited time', 'act now', 'last chance', 'confirm your identity', 'unusual activity', 'click here', 'act immediately'],
    'es': ['urgente', 'inmediatamente', 'requiere accion', 'verificar cuenta', 'suspendido', 'bloqueado', 'no autorizado', 'caducar', '24 horas', '48 horas', 'tiempo limitado', 'actua ahora'],
    'fr': ['urgent', 'immédiatement', 'action requise', 'verifier compte', 'suspendu', 'verrouille', 'non autorise', 'expirer', '24 heures', '48 heures', 'temps limite', 'agissez maintenant'],
    'de': ['dringend', 'sofort', 'aktion erforderlich', 'konto verifizieren', 'gesperrt', 'nicht autorisiert', 'ablaufen', '24 stunden', '48 stunden', 'begrenzte zeit', 'jetzt handeln'],
    'zh': ['紧急', '立即', '需要操作', '验证账户', '暂停', '锁定', '未经授权', '过期', '24小时', '48小时', '限时', '立即行动'],
    'ru': ['срочно', 'немедленно', 'требуется действие', 'проверить аккаунт', 'приостановлен', 'заблокирован', 'не авторизован', 'истекает', '24 часа', '48 часов', 'ограниченное время', 'действуйте сейчас']
}

def detect_language(text):
    try:
        if not text or len(text) < 20:
            return 'en'
        return detect(text)
    except LangDetectException:
        return 'en'

def analyze_content_language(html_content):
    if not html_content:
        return {'language': 'unknown', 'urgency_score': 0}
    
    soup = BeautifulSoup(html_content, 'html.parser')
    text = soup.get_text()
    
    language = detect_language(text)
    
    urgency_score = 0
    patterns = URGENCY_PATTERNS.get(language, URGENCY_PATTERNS['en'])
    
    text_lower = text.lower()
    for pattern in patterns:
        if pattern.lower() in text_lower:
            urgency_score += 0.1
    
    return {
        'language': language,
        'urgency_score': min(urgency_score, 1.0),
        'detected_patterns': [p for p in patterns if p.lower() in text_lower]
    }

def analyze_qr_codes(html_content):
    if not html_content:
        return []
    
    import re
    
    qr_patterns = [
        r'data:image/png;base64,[A-Za-z0-9+/=]+',
        r'data:image/jpeg;base64,[A-Za-z0-9+/=]+',
        r'qr[_-]?code',
        r'qrcode'
    ]
    
    found_qrs = []
    for pattern in qr_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        found_qrs.extend(matches)
    
    return found_qrs