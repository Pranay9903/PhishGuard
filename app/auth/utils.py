from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import base64
import zxcvbn
import secrets

def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256:100000', salt_length=32)

def verify_password(password, password_hash):
    return check_password_hash(password_hash, password)

def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(secret, username, issuer='PhishGuard'):
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)

def generate_totp_qr(secret, username):
    uri = get_totp_uri(secret, username)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return base64.b64encode(buffer.getvalue()).decode()

def check_password_strength(password):
    result = zxcvbn.zxcvbn(password)
    return {
        'score': result['score'],
        'crack_time': result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
        'feedback': result['feedback']['warning'],
        'suggestions': result['feedback']['suggestions']
    }

def generate_api_key():
    return secrets.token_hex(32)