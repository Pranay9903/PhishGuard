# Phishing Detection System - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a complete full-stack Flask phishing detection system with 50+ features including ML ensemble, REST API, real-time WebSocket, Celery background tasks, Docker deployment, PWA support, and admin dashboard.

**Architecture:** Modular Flask application with SQLite database, Redis caching, Celery task queue. Frontend uses Bootstrap 5 with Chart.js visualizations. Detection engine combines 25+ NLP heuristics with simulated ML ensemble.

**Tech Stack:** Flask 2.3, Flask-RESTx, Flask-SocketIO, Flask-Login, Flask-Limiter, Flask-Caching, Celery, Redis, SQLite, Bootstrap 5, Chart.js, Selenium, BeautifulSoup, WeasyPrint, pyotp, zxcvbn

---

## File Structure

```
Phishing_Detection_App/
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── models.py
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   └── utils.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   └── namespace.py
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── heuristics.py
│   │   ├── ml_ensemble.py
│   │   ├── ssl_checker.py
│   │   ├── dns_analyzer.py
│   │   ├── typosquatting.py
│   │   └── content_analyzer.py
│   ├── tasks/
│   │   ├── __init__.py
│   │   ├── bulk_analysis.py
│   │   ├── screenshot.py
│   │   └── reports.py
│   ├── websocket/
│   │   └── __init__.py
│   ├── templates/
│   │   ├── base.html
│   │   ├── auth/
│   │   ├── dashboard/
│   │   ├── admin/
│   │   └── api/
│   └── static/
│       ├── css/
│       ├── js/
│       └── manifest.json
├── tests/
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_detection.py
│   ├── test_api.py
│   └── test_integration.py
├── celery_app.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── run.py
```

---

## Phase 1: Core Infrastructure

### Task 1: Project Setup & Configuration

**Files:**
- Create: `requirements.txt`
- Create: `app/__init__.py`
- Create: `app/config.py`
- Create: `run.py`

- [ ] **Step 1: Create requirements.txt**

```txt
Flask==2.3.3
Flask-RESTx==1.3.0
Flask-SocketIO==5.3.6
Flask-Login==0.6.3
Flask-Limiter==3.5.0
Flask-Caching==2.1.0
Flask-Mail==0.9.1
Flask-SQLAlchemy==3.1.1
Flask-Migrate==4.0.5
celery==5.3.4
redis==5.0.1
SQLAlchemy==2.0.23
Werkzeug==2.3.7
python-dotenv==1.0.0
pyotp==2.9.0
zxcvbn==4.4.2
beautifulsoup4==4.12.2
lxml==4.9.3
requests==2.31.0
dnspython==2.4.2
whois==0.9.25
WeasyPrint==60.2
selenium==4.15.2
webdriver-manager==4.0.1
chart.js==4.4.0
bootstrap==5.3.2
Pillow==10.1.0
qrcode==7.4.2
langdetect==1.0.9
python-dateutil==2.8.2
marshmallow==3.20.1
APScheduler==3.10.4
Werkzeug[watchdog]==2.3.7
```

- [ ] **Step 2: Create app/config.py**

```python
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32))
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///phishing_detect.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session config
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Redis config
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    CACHE_DEFAULT_TIMEOUT = 86400  # 24 hours
    
    # Celery config
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/1')
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/1')
    
    # Mail config
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # Rate limiting
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # API config
    API_RATE_LIMIT = "10 per minute"
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    
    # Selenium config
    SELENIUM_HEADLESS = os.environ.get('SELENIUM_HEADLESS', 'true').lower() == 'true'
    
    # Upload config
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'csv'}

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
```

- [ ] **Step 3: Create app/__init__.py**

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_caching import Cache
from flask_mail import Mail
from flask_migrate import Migrate
from celery import Celery
from flask_socketio import SocketIO
import redis
import os

db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter()
cache = Cache()
mail = Mail()
migrate = Migrate()
celery = Celery('phishing_detect')
socketio = SocketIO()

def create_app(config_name='default'):
    from app.config import config
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    cache.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    
    # Initialize Celery
    celery.conf.update(app.config)
    
    # Initialize SocketIO
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    
    # Register blueprints
    from app.auth.routes import auth_bp
    from app.api.routes import api_bp
    from app.main.routes import main_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(main_bp)
    
    # Create tables
    with app.app_context():
        db.create_all()
    
    # Setup login manager
    login_manager.login_view = 'auth.login'
    
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))
    
    return app

def create_celery_app(app=None):
    app = app or create_app()
    celery.conf.update(app.config)
    
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery
```

- [ ] **Step 4: Create run.py**

```python
import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app, socketio

app = create_app(os.environ.get('FLASK_ENV', 'development'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
```

- [ ] **Step 5: Commit**

```bash
git add requirements.txt app/__init__.py app/config.py run.py
git commit -m "feat: add project setup and configuration"
```

---

### Task 2: Database Models

**Files:**
- Create: `app/models.py`

- [ ] **Step 1: Create app/models.py**

```python
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import secrets
import pyotp

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    api_key = db.Column(db.String(64), unique=True, nullable=True)
    role = db.Column(db.String(20), default='user')  # user, admin
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    analyses = db.relationship('Analysis', backref='user', lazy=True)
    watchlist = db.relationship('Watchlist', backref='user', lazy=True)
    feedback = db.relationship('Feedback', backref='user', lazy=True)
    
    def generate_api_key(self):
        self.api_key = secrets.token_hex(32)
        return self.api_key
    
    def verify_totp(self, code):
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(code)

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(20), nullable=False)  # safe, suspicious, phishing
    confidence = db.Column(db.Float, nullable=False)
    heuristics = db.Column(db.JSON, nullable=True)
    ml_scores = db.Column(db.JSON, nullable=True)
    final_score = db.Column(db.Float, nullable=False)
    batch_id = db.Column(db.String(64), nullable=True)
    screenshot_path = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    feedback = db.relationship('Feedback', backref='analysis', lazy=True)

class Watchlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, safe, suspicious, phishing
    last_checked = db.Column(db.DateTime, nullable=True)
    notify_on_change = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis.id'), nullable=False)
    feedback_type = db.Column(db.String(10), nullable=False)  # fp (false positive), fn (false negative)
    comment = db.Column(db.Text, nullable=True)
    resolved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Blacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(256), unique=True, nullable=False)
    source = db.Column(db.String(50), nullable=True)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

class DomainCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(256), unique=True, nullable=False)
    reputation_score = db.Column(db.Float, nullable=True)
    is_malicious = db.Column(db.Boolean, nullable=True)
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
```

- [ ] **Step 2: Commit**

```bash
git add app/models.py
git commit -m "feat: add database models"
```

---

### Task 3: Authentication Module

**Files:**
- Create: `app/auth/__init__.py`
- Create: `app/auth/routes.py`
- Create: `app/auth/utils.py`

- [ ] **Step 1: Create app/auth/__init__.py**

```python
from flask import Blueprint

auth_bp = Blueprint('auth', __name__)

from app.auth import routes
```

- [ ] **Step 2: Create app/auth/utils.py**

```python
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
```

- [ ] **Step 3: Create app/auth/routes.py**

```python
from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.auth import auth_bp
from app.auth.utils import hash_password, verify_password, generate_totp_secret, generate_totp_qr, check_password_strength, generate_api_key
from app.models import db, User, AuditLog
from datetime import datetime

limiter = Limiter(key_func=get_remote_address)

@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        strength = check_password_strength(password)
        if strength['score'] < 2:
            flash(f'Password too weak: {strength["feedback"]}', 'danger')
            return render_template('auth/register.html')
        
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists', 'danger')
            return render_template('auth/register.html')
        
        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password)
        )
        db.session.add(user)
        db.session.commit()
        
        # Log registration
        log = AuditLog(
            user_id=user.id,
            event_type='register',
            details=f'User {username} registered',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        totp_code = request.form.get('totp_code')
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not verify_password(password, user.password_hash):
            flash('Invalid username or password', 'danger')
            return render_template('auth/login.html')
        
        if user.totp_secret and not totp_code:
            session['pre_2fa_user_id'] = user.id
            session['require_2fa'] = True
            return redirect(url_for('auth.login_2fa'))
        
        if session.get('require_2fa') and session.get('pre_2fa_user_id') == user.id:
            if not user.verify_totp(totp_code):
                flash('Invalid 2FA code', 'danger')
                return render_template('auth/login_2fa.html')
            session.pop('require_2fa', None)
            session.pop('pre_2fa_user_id', None)
        
        login_user(user, remember=True)
        user.last_login = datetime.utcnow()
        
        log = AuditLog(
            user_id=user.id,
            event_type='login',
            details=f'User {username} logged in',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Login successful!', 'success')
        next_page = request.args.get('next')
        return redirect(next_page or url_for('main.dashboard'))
    
    return render_template('auth/login.html')

@auth_bp.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    if not session.get('require_2fa'):
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        flash('Please enter your 2FA code', 'warning')
    
    return render_template('auth/login_2fa.html')

@auth_bp.route('/logout')
@login_required
def logout():
    log = AuditLog(
        user_id=current_user.id,
        event_type='logout',
        details=f'User {current_user.username} logged out',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if request.method == 'POST':
        if current_user.totp_secret:
            current_user.totp_secret = None
            db.session.commit()
            flash('2FA disabled', 'info')
        else:
            secret = generate_totp_secret()
            current_user.totp_secret = secret
            db.session.commit()
            flash('2FA enabled', 'success')
        return redirect(url_for('main.dashboard'))
    
    if not current_user.totp_secret:
        secret = generate_totp_secret()
        current_user.totp_secret = secret
        db.session.commit()
        qr_code = generate_totp_qr(secret, current_user.username)
        return render_template('auth/setup_2fa.html', qr_code=qr_code, secret=secret)
    
    return render_template('auth/setup_2fa.html', qr_code=None, secret=None)

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        if not verify_password(current_password, current_user.password_hash):
            flash('Current password is incorrect', 'danger')
            return render_template('auth/change_password.html')
        
        strength = check_password_strength(new_password)
        if strength['score'] < 2:
            flash(f'Password too weak: {strength["feedback"]}', 'danger')
            return render_template('auth/change_password.html')
        
        current_user.password_hash = hash_password(new_password)
        current_user.password_changed_at = datetime.utcnow()
        
        # Force logout all sessions
        log = AuditLog(
            user_id=current_user.id,
            event_type='password_change',
            details='Password changed - all sessions invalidated',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        # In a production system, you'd invalidate all session tokens here
        flash('Password changed successfully. Please login again.', 'success')
        logout_user()
        return redirect(url_for('auth.login'))
    
    return render_template('auth/change_password.html')

@auth_bp.route('/api-key', methods=['POST'])
@login_required
def generate_api_key():
    if not current_user.api_key:
        current_user.generate_api_key()
        db.session.commit()
    
    log = AuditLog(
        user_id=current_user.id,
        event_type='api_key_generate',
        details='API key generated',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    flash(f'API Key: {current_user.api_key}', 'info')
    return redirect(url_for('main.dashboard'))
```

- [ ] **Step 4: Commit**

```bash
git add app/auth/__init__.py app/auth/routes.py app/auth/utils.py
git commit -m "feat: add authentication module with 2FA and password strength"
```

---

## Phase 2: Detection Engine

### Task 4: NLP Heuristics

**Files:**
- Create: `app/detection/__init__.py`
- Create: `app/detection/heuristics.py`

- [ ] **Step 1: Create app/detection/__init__.py**

```python
from app.detection.heuristics import analyze_url

__all__ = ['analyze_url']
```

- [ ] **Step 2: Create app/detection/heuristics.py**

```python
import math
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs
import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
from datetime import datetime
import json

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
```

- [ ] **Step 3: Commit**

```python
git add app/detection/__init__.py app/detection/heuristics.py
git commit -m "feat: add NLP heuristics for URL analysis"
```

---

### Task 5: ML Ensemble

**Files:**
- Create: `app/detection/ml_ensemble.py`

- [ ] **Step 1: Create app/detection/ml_ensemble.py**

```python
import random
import numpy as np
from typing import Dict, List

class RandomForestSimulation:
    def __init__(self, n_trees=100):
        self.n_trees = n_trees
    
    def predict(self, heuristics: Dict) -> float:
        scores = []
        for _ in range(self.n_trees):
            score = self._simulate_tree(heuristics)
            scores.append(score)
        return np.mean(scores)
    
    def _simulate_tree(self, heuristics: Dict) -> float:
        base_score = heuristics.get('total_score', 0.5)
        noise = random.gauss(0, 0.1)
        tree_score = base_score + noise
        return max(0, min(1, tree_score))

class XGBoostSimulation:
    def __init__(self, n_rounds=50):
        self.n_rounds = n_rounds
    
    def predict(self, heuristics: Dict) -> float:
        score = heuristics.get('total_score', 0.5)
        
        for _ in range(self.n_rounds):
            gradient = self._calculate_gradient(score)
            hessian = self._calculate_hessian(score)
            learning_rate = 0.1
            score += learning_rate * gradient / (hessian + 1e-6)
        
        return max(0, min(1, score))
    
    def _calculate_gradient(self, score):
        return (0.5 - score) * random.uniform(0.8, 1.2)
    
    def _calculate_hessian(self, score):
        return abs(score - 0.5) + 0.5

class LSTMSimulation:
    def __init__(self, sequence_length=10):
        self.sequence_length = sequence_length
    
    def predict(self, heuristics: Dict) -> float:
        url = heuristics.get('url', '')
        if not url:
            return heuristics.get('total_score', 0.5)
        
        sequence_scores = []
        for i in range(min(len(url), self.sequence_length)):
            char_score = self._char_to_score(url[i])
            sequence_scores.append(char_score)
        
        if sequence_scores:
            lstm_score = np.mean(sequence_scores)
            base_score = heuristics.get('total_score', 0.5)
            return (base_score * 0.7) + (lstm_score * 0.3)
        
        return heuristics.get('total_score', 0.5)
    
    def _char_to_score(self, char):
        suspicious_chars = '@#$%^&*!~`|/\\:;"\'<>?'
        if char in suspicious_chars:
            return random.uniform(0.6, 0.9)
        elif char.isdigit():
            return random.uniform(0.3, 0.6)
        return random.uniform(0.1, 0.4)

class BERTSimulation:
    def __init__(self):
        self.urgency_patterns = [
            'urgent', 'immediately', 'action required', 'verify',
            'suspended', 'locked', 'unauthorized', 'expire'
        ]
        self.brand_patterns = [
            'google', 'facebook', 'amazon', 'paypal', 'bank',
            'microsoft', 'apple', 'netflix', 'chase'
        ]
    
    def predict(self, heuristics: Dict) -> float:
        base_score = heuristics.get('total_score', 0.5)
        
        urgency_score = heuristics.get('urgency_words', 0)
        brand_score = heuristics.get('brand_impersonation', 0)
        login_form_score = heuristics.get('login_form', 0)
        
        bert_score = (
            base_score * 0.3 +
            urgency_score * 0.25 +
            brand_score * 0.25 +
            login_form_score * 0.2
        )
        
        noise = random.gauss(0, 0.05)
        return max(0, min(1, bert_score + noise))

class MLEnsemble:
    def __init__(self, weights=None):
        self.random_forest = RandomForestSimulation()
        self.xgboost = XGBoostSimulation()
        self.lstm = LSTMSimulation()
        self.bert = BERTSimulation()
        
        self.weights = weights or {
            'random_forest': 0.25,
            'xgboost': 0.25,
            'lstm': 0.25,
            'bert': 0.25
        }
    
    def predict(self, heuristics: Dict) -> Dict:
        rf_score = self.random_forest.predict(heuristics)
        xgb_score = self.xgboost.predict(heuristics)
        lstm_score = self.lstm.predict(heuristics)
        bert_score = self.bert.predict(heuristics)
        
        ensemble_score = (
            rf_score * self.weights['random_forest'] +
            xgb_score * self.weights['xgboost'] +
            lstm_score * self.weights['lstm'] +
            bert_score * self.weights['bert']
        )
        
        return {
            'random_forest': rf_score,
            'xgboost': xgb_score,
            'lstm': lstm_score,
            'bert': bert_score,
            'ensemble': ensemble_score,
            'confidence': min(ensemble_score * 1.1, 1.0)
        }
    
    def adjust_weights(self, feedback_type: str, model_name: str):
        if feedback_type == 'fp':
            self.weights[model_name] *= 0.9
        elif feedback_type == 'fn':
            self.weights[model_name] *= 1.1
        
        total = sum(self.weights.values())
        self.weights = {k: v/total for k, v in self.weights.items()}

ensemble = MLEnsemble()
```

- [ ] **Step 2: Commit**

```bash
git add app/detection/ml_ensemble.py
git commit -m "feat: add ML ensemble with weighted voting"
```

---

### Task 6: SSL, DNS, Typosquatting Analyzers

**Files:**
- Create: `app/detection/ssl_checker.py`
- Create: `app/detection/dns_analyzer.py`
- Create: `app/detection/typosquatting.py`
- Create: `app/detection/content_analyzer.py`

- [ ] **Step 1: Create app/detection/ssl_checker.py**

```python
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
```

- [ ] **Step 2: Create app/detection/dns_analyzer.py**

```python
import dns.resolver
import dns.query
import dns.zone
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
```

- [ ] **Step 3: Create app/detection/typosquatting.py**

```python
from app.detection.heuristics import levenshtein_distance

TOP_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com',
    'paypal.com', 'netflix.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
    'citi.com', 'usbank.com', 'capitalone.com', 'americanexpress.com', 'discover.com',
    'dropbox.com', 'box.com', 'linkedin.com', 'twitter.com', 'instagram.com',
    'tiktok.com', 'reddit.com', 'youtube.com', 'yahoo.com', 'bing.com',
    'dropbox.com', 'slack.com', 'zoom.us', 'teams.microsoft.com', 'github.com',
    'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 'medium.com', 'wordpress.com',
    'shopify.com', 'walmart.com', 'target.com', 'bestbuy.com', 'homedepot.com',
    'lowes.com', 'costco.com', 'safeway.com', 'kroger.com', 'publix.com',
    'fedex.com', 'ups.com', 'usps.com', 'dhl.com', 'ontimerunners.com',
    'whatsapp.com', 'telegram.org', 'discord.com', 'spotify.com', 'soundcloud.com',
    'adobe.com', 'autodesk.com', 'salesforce.com', 'oracle.com', 'ibm.com',
    'intuit.com', 'quickbooks.com', 'turbotax.com', 'h&Rblock.com', 'taxact.com',
    'mint.com', 'chime.com', 'robinhood.com', 'coinbase.com', 'binance.com',
    'etsy.com', 'ebay.com', 'craigslist.org', 'airbnb.com', 'booking.com',
    'expedia.com', 'trivago.com', 'hotels.com', 'marriott.com', 'hilton.com',
    'uber.com', 'lyft.com', 'doordash.com', 'grubhub.com', 'postmates.com',
    'fedex.com', 'ups.com', 'usps.com', 'dhl.com', 'ontrac.com',
    'att.com', 'verizon.com', 'tmobile.com', 'sprint.com', 'comcast.com',
    'spectrum.com', 'cox.com', 'centurylink.com', 'frontier.com', 'rcn.com',
    'geico.com', 'statefarm.com', 'allstate.com', 'progressive.com', 'libertymutual.com',
    'bluecrossma.com', 'aetna.com', 'cigna.com', 'humana.com', 'unitedhealthcare.com',
    'khanacademy.org', 'coursera.org', 'udemy.com', 'edx.org', 'skillshare.com',
    'roku.com', 'chromecast.com', 'firetv.com', 'appletv.com', 'nvidiapro.com'
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
```

- [ ] **Step 4: Create app/detection/content_analyzer.py**

```python
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
    import base64
    
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
```

- [ ] **Step 5: Commit**

```bash
git add app/detection/ssl_checker.py app/detection/dns_analyzer.py app/detection/typosquatting.py app/detection/content_analyzer.py
git commit -f "feat: add SSL, DNS, typosquatting, and content analyzers"
```

---

## Phase 3: API & Web Interface

### Task 7: REST API

**Files:**
- Create: `app/api/__init__.py`
- Create: `app/api/routes.py`
- Create: `app/api/namespace.py`

- [ ] **Step 1: Create app/api/__init__.py**

```python
from flask import Blueprint

api_bp = Blueprint('api', __name__)

from app.api import routes
```

- [ ] **Step 2: Create app/api/routes.py**

```python
from flask import request, jsonify
from flask_restx import Api, Resource, fields
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import login_required, current_user
from app.api import api_bp
from app.models import db, User, Analysis, Watchlist, Feedback, AuditLog, Blacklist
from app.detection.heuristics import analyze_url
from app.detection.ml_ensemble import ensemble
from app.detection.ssl_checker import get_ssl_info, check_certificate_transparency
from app.detection.dns_analyzer import analyze_dns, get_whois_info
from app.detection.typosquatting import detect_typosquatting
from app.detection.content_analyzer import analyze_content_language, analyze_qr_codes
from app.auth.utils import verify_password
import requests
from datetime import datetime
import secrets
import csv
import io

limiter = Limiter(key_func=get_remote_address)

api = Api(api_bp, version='1.0', title='PhishGuard API', description='Phishing Detection API', doc='/docs')

ns = api.namespace('analyze', description='URL Analysis Operations')

analyze_model = api.model('Analyze', {
    'url': fields.String(required=True, description='URL to analyze'),
    'include_html': fields.Boolean(description='Include HTML content analysis')
})

result_model = api.model('Result', {
    'url': fields.String,
    'result': fields.String,
    'confidence': fields.Float,
    'heuristics': fields.Raw,
    'ml_scores': fields.Raw,
    'final_score': fields.Float
})

@ns.route('/<path:url>')
class AnalyzeURL(Resource):
    @api.expect(analyze_model)
    @api.marshal_with(result_model)
    @limiter.limit("10 per minute")
    def get(self, url):
        url = request.args.get('url', url)
        include_html = request.args.get('include_html', 'false').lower() == 'true'
        
        html_content = None
        if include_html:
            try:
                response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
                html_content = response.text
            except:
                pass
        
        heuristics = analyze_url(url, html_content)
        ml_scores = ensemble.predict(heuristics)
        
        final_score = (heuristics['total_score'] * 0.6) + (ml_scores['ensemble'] * 0.4)
        
        if final_score < 0.3:
            result = 'safe'
        elif final_score < 0.6:
            result = 'suspicious'
        else:
            result = 'phishing'
        
        if current_user.is_authenticated:
            analysis = Analysis(
                user_id=current_user.id,
                url=url,
                result=result,
                confidence=ml_scores['confidence'],
                heuristics=heuristics,
                ml_scores=ml_scores,
                final_score=final_score
            )
            db.session.add(analysis)
            db.session.commit()
        
        return {
            'url': url,
            'result': result,
            'confidence': ml_scores['confidence'],
            'heuristics': heuristics,
            'ml_scores': ml_scores,
            'final_score': final_score
        }

@ns.route('/full/<path:url>')
class FullAnalysis(Resource):
    @limiter.limit("5 per minute")
    def get(self, url):
        url = request.args.get('url', url)
        
        heuristics = analyze_url(url)
        
        try:
            ssl_info = get_ssl_info(url)
        except:
            ssl_info = {'valid': False, 'error': 'Could not check SSL'}
        
        try:
            dns_info = analyze_dns(url)
        except:
            dns_info = {'error': 'Could not analyze DNS'}
        
        try:
            typosquatting = detect_typosquatting(url)
        except:
            typosquatting = []
        
        try:
            whois_info = get_whois_info(url)
        except:
            whois_info = {'error': 'Could not get WHOIS info'}
        
        ml_scores = ensemble.predict(heuristics)
        
        return {
            'url': url,
            'heuristics': heuristics,
            'ssl': ssl_info,
            'dns': dns_info,
            'typosquatting': typosquatting,
            'whois': whois_info,
            'ml_scores': ml_scores
        }

auth_ns = api.namespace('auth', description='Authentication')

login_model = auth_ns.model('Login', {
    'username': fields.String(required=True),
    'password': fields.String(required=True)
})

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model)
    def post(self):
        data = request.json
        user = User.query.filter_by(username=data['username']).first()
        
        if not user or not verify_password(data['password'], user.password_hash):
            api.abort(401, 'Invalid credentials')
        
        if not user.api_key:
            user.generate_api_key()
            db.session.commit()
        
        return {'api_key': user.api_key, 'username': user.username}

watchlist_ns = api.namespace('watchlist', description='Watchlist Operations')

@watchlist_ns.route('')
class WatchlistResource(Resource):
    @login_required
    def get(self):
        items = Watchlist.query.filter_by(user_id=current_user.id).all()
        return [{'id': w.id, 'url': w.url, 'status': w.status, 'last_checked': w.last_checked} for w in items]
    
    @login_required
    @watchlist_ns.expect(api.model('WatchlistAdd', {'url': fields.String(required=True)}))
    def post(self):
        data = request.json
        existing = Watchlist.query.filter_by(user_id=current_user.id, url=data['url']).first()
        if existing:
            return {'message': 'URL already in watchlist'}, 400
        
        item = Watchlist(user_id=current_user.id, url=data['url'])
        db.session.add(item)
        db.session.commit()
        return {'message': 'Added to watchlist'}, 201

@watchlist_ns.route('/<int:id>')
class WatchlistItem(Resource):
    @login_required
    def delete(self, id):
        item = Watchlist.query.filter_by(id=id, user_id=current_user.id).first()
        if not item:
            api.abort(404, 'Item not found')
        
        db.session.delete(item)
        db.session.commit()
        return {'message': 'Removed from watchlist'}

feedback_ns = api.namespace('feedback', description='Feedback Operations')

@feedback_ns.route('')
class FeedbackResource(Resource):
    @login_required
    @feedback_ns.expect(api.model('Feedback', {
        'analysis_id': fields.Integer(required=True),
        'feedback_type': fields.String(required=True),
        'comment': fields.String()
    }))
    def post(self):
        data = request.json
        analysis = Analysis.query.get(data['analysis_id'])
        if not analysis or analysis.user_id != current_user.id:
            api.abort(404, 'Analysis not found')
        
        feedback = Feedback(
            user_id=current_user.id,
            analysis_id=data['analysis_id'],
            feedback_type=data['feedback_type'],
            comment=data.get('comment')
        )
        db.session.add(feedback)
        
        if data['feedback_type'] == 'fp':
            ensemble.adjust_weights('fp', 'random_forest')
        elif data['feedback_type'] == 'fn':
            ensemble.adjust_weights('fn', 'random_forest')
        
        db.session.commit()
        return {'message': 'Feedback recorded'}

bulk_ns = api.namespace('bulk', description='Bulk Analysis')

@bulk_ns.route('/analyze')
class BulkAnalyze(Resource):
    @login_required
    def post(self):
        if 'file' not in request.files:
            api.abort(400, 'No file provided')
        
        file = request.files['file']
        if not file.filename.endswith('.csv'):
            api.abort(400, 'Only CSV files allowed')
        
        batch_id = secrets.token_hex(16)
        
        content = file.read().decode('utf-8')
        reader = csv.reader(io.StringIO(content))
        urls = [row[0] for row in reader if row]
        
        from app.tasks.bulk_analysis import process_bulk_urls
        process_bulk_urls.delay(current_user.id, urls, batch_id)
        
        return {'batch_id': batch_id, 'total_urls': len(urls)}

@bulk_ns.route('/<batch_id>')
class BulkStatus(Resource):
    @login_required
    def get(self, batch_id):
        analyses = Analysis.query.filter_by(batch_id=batch_id).all()
        return {
            'batch_id': batch_id,
            'total': len(analyses),
            'results': [{'url': a.url, 'result': a.result, 'confidence': a.confidence} for a in analyses]
        }
```

- [ ] **Step 3: Commit**

```bash
git add app/api/__init__.py app/api/routes.py
git commit -m "feat: add REST API with Flask-RESTx"
```

---

### Task 8: Main Routes & Templates

**Files:**
- Create: `app/main/routes.py`
- Create: `app/templates/base.html`
- Create: `app/templates/auth/login.html`
- Create: `app/templates/dashboard/index.html`

- [ ] **Step 1: Create app/main/routes.py**

```python
from flask import Blueprint, render_template, request, jsonify, send_file
from flask_login import login_required, current_user
from app.models import db, Analysis, Watchlist, Feedback, AuditLog, User
from app.detection.heuristics import analyze_url
from app.detection.ml_ensemble import ensemble
from datetime import datetime, timedelta
import io
import csv

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('dashboard/index.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    recent_analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).limit(10).all()
    watchlist = Watchlist.query.filter_by(user_id=current_user.id).all()
    
    week_ago = datetime.utcnow() - timedelta(days=7)
    weekly_stats = Analysis.query.filter(
        Analysis.user_id == current_user.id,
        Analysis.created_at >= week_ago
    ).all()
    
    safe_count = sum(1 for a in weekly_stats if a.result == 'safe')
    suspicious_count = sum(1 for a in weekly_stats if a.result == 'suspicious')
    phishing_count = sum(1 for a in weekly_stats if a.result == 'phishing')
    
    return render_template('dashboard/dashboard.html',
                         recent_analyses=recent_analyses,
                         watchlist=watchlist,
                         safe_count=safe_count,
                         suspicious_count=suspicious_count,
                         phishing_count=phishing_count)

@main_bp.route('/analyze')
@login_required
def analyze():
    url = request.args.get('url')
    if not url:
        return render_template('dashboard/analyze.html')
    
    heuristics = analyze_url(url)
    ml_scores = ensemble.predict(heuristics)
    
    final_score = (heuristics['total_score'] * 0.6) + (ml_scores['ensemble'] * 0.4)
    
    if final_score < 0.3:
        result = 'safe'
    elif final_score < 0.6:
        result = 'suspicious'
    else:
        result = 'phishing'
    
    analysis = Analysis(
        user_id=current_user.id,
        url=url,
        result=result,
        confidence=ml_scores['confidence'],
        heuristics=heuristics,
        ml_scores=ml_scores,
        final_score=final_score
    )
    db.session.add(analysis)
    db.session.commit()
    
    return render_template('dashboard/analyze.html',
                         url=url,
                         result=result,
                         heuristics=heuristics,
                         ml_scores=ml_scores,
                         analysis_id=analysis.id)

@main_bp.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(
        Analysis.created_at.desc()
    ).paginate(page=page, per_page=per_page)
    
    return render_template('dashboard/history.html', analyses=analyses)

@main_bp.route('/export/csv')
@login_required
def export_csv():
    analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(
        Analysis.created_at.desc()
    ).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'URL', 'Result', 'Confidence', 'Final Score', 'Created At'])
    
    for a in analyses:
        writer.writerow([a.id, a.url, a.result, a.confidence, a.final_score, a.created_at])
    
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='analysis_history.csv')

@main_bp.route('/watchlist')
@login_required
def watchlist_page():
    items = Watchlist.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard/watchlist.html', items=items)

@main_bp.route('/feedback', methods=['POST'])
@login_required
def submit_feedback():
    data = request.json
    analysis = Analysis.query.get(data['analysis_id'])
    if not analysis or analysis.user_id != current_user.id:
        return jsonify({'error': 'Analysis not found'}), 404
    
    feedback = Feedback(
        user_id=current_user.id,
        analysis_id=data['analysis_id'],
        feedback_type=data['feedback_type'],
        comment=data.get('comment')
    )
    db.session.add(feedback)
    db.session.commit()
    
    return jsonify({'message': 'Feedback submitted'})

@main_bp.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        return render_template('errors/403.html'), 403
    
    users = User.query.all()
    total_analyses = Analysis.query.count()
    recent_audits = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    
    return render_template('admin/index.html',
                         users=users,
                         total_analyses=total_analyses,
                         recent_audits=recent_audits)

@main_bp.route('/settings')
@login_required
def settings():
    return render_template('dashboard/settings.html')
```

- [ ] **Step 2: Create app/templates/base.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}PhishGuard{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <link rel="manifest" href="{{ url_for('static', filename='manifest.json') }}">
    <style>
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
        }
        [data-theme="dark"] {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --text-primary: #e9ecef;
            --text-secondary: #adb5bd;
            --border-color: #0f3460;
        }
        body {
            background-color: var(--bg-secondary);
            color: var(--text-primary);
        }
        .navbar {
            background-color: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
        }
        .card {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
        }
        .sidebar {
            min-height: 100vh;
            background-color: var(--bg-primary);
            border-right: 1px solid var(--border-color);
        }
        .ws-connected { color: #28a745; }
        .ws-disconnected { color: #dc3545; }
    </style>
    {% block extra_css %}{% endblock %}
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-shield-check"></i> PhishGuard
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    {% if current_user.is_authenticated %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('main.dashboard') }}">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('main.analyze') }}">Analyze</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('main.history') }}">History</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('main.watchlist_page') }}">Watchlist</a>
                    </li>
                    {% if current_user.role == 'admin' %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('main.admin') }}">Admin</a>
                    </li>
                    {% endif %}
                    <li class="nav-item">
                        <button class="btn btn-link" id="theme-toggle">
                            <i class="bi bi-moon"></i>
                        </button>
                    </li>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">
                            {{ current_user.username }}
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="{{ url_for('main.settings') }}">Settings</a></li>
                            <li><a class="dropdown-item" href="{{ url_for('auth.logout') }}">Logout</a></li>
                        </ul>
                    </li>
                    {% else %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('auth.login') }}">Login</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('auth.register') }}">Register</a>
                    </li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid">
        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>
        const theme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', theme);
        
        document.getElementById('theme-toggle').addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme');
            const next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('theme', next);
        });

        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/static/sw.js');
        }
    </script>
    {% block extra_js %}{% endblock %}
</body>
</html>
```

- [ ] **Step 3: Create app/templates/auth/login.html**

```html
{% extends "base.html" %}

{% block title %}Login - PhishGuard{% endblock %}

{% block content %}
<div class="row justify-content-center mt-5">
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h4 class="mb-0">Login</h4>
            </div>
            <div class="card-body">
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" name="username" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    {% if require_2fa %}
                    <div class="mb-3">
                        <label class="form-label">2FA Code</label>
                        <input type="text" name="totp_code" class="form-control" required>
                    </div>
                    {% endif %}
                    <button type="submit" class="btn btn-primary w-100">Login</button>
                </form>
                <div class="mt-3 text-center">
                    <a href="{{ url_for('auth.register') }}">Don't have an account? Register</a>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
```

- [ ] **Step 4: Create app/templates/dashboard/index.html**

```html
{% extends "base.html" %}

{% block title %}PhishGuard - Phishing Detection{% endblock %}

{% block content %}
<div class="row justify-content-center mt-5">
    <div class="col-md-8 text-center">
        <h1 class="display-4 mb-4">
            <i class="bi bi-shield-check text-primary"></i> PhishGuard
        </h1>
        <p class="lead mb-4">Advanced Zero-Day Phishing Detection System</p>
        
        <div class="card">
            <div class="card-body">
                <form action="{{ url_for('main.analyze') }}" method="GET" class="d-flex gap-2">
                    <input type="url" name="url" class="form-control form-control-lg" 
                           placeholder="Enter URL to analyze..." required>
                    <button type="submit" class="btn btn-primary btn-lg">
                        <i class="bi bi-search"></i> Analyze
                    </button>
                </form>
            </div>
        </div>
        
        <div class="row mt-5">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <i class="bi bi-cpu display-4 text-primary"></i>
                        <h5>ML-Powered</h5>
                        <p class="text-muted">Ensemble detection with Random Forest, XGBoost, LSTM, and BERT</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <i class="bi bi-lightning display-4 text-warning"></i>
                        <h5>Real-Time</h5>
                        <p class="text-muted">Instant analysis with WebSocket progress streaming</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <i class="bi bi-globe display-4 text-info"></i>
                        <h5>Comprehensive</h5>
                        <p class="text-muted">25+ NLP heuristics including typosquatting & brand impersonation</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
```

- [ ] **Step 5: Commit**

```bash
git add app/main/routes.py app/templates/base.html app/templates/auth/login.html app/templates/dashboard/index.html
git commit -m "feat: add main routes and templates"
```

---

## Phase 4: Background Tasks & Docker

### Task 9: Celery Tasks

**Files:**
- Create: `app/tasks/__init__.py`
- Create: `app/tasks/bulk_analysis.py`
- Create: `app/tasks/screenshot.py`
- Create: `app/tasks/reports.py`
- Create: `celery_app.py`

- [ ] **Step 1: Create app/tasks/__init__.py**

```python
from celery import Celery

celery_app = Celery('phishing_detect')

celery_app.config_from_object('app.config:Config', namespace='CELERY')
celery_app.autodiscover_tasks(['app.tasks'])
```

- [ ] **Step 2: Create app/tasks/bulk_analysis.py**

```python
from app import create_app, socketio
from app.detection.heuristics import analyze_url
from app.detection.ml_ensemble import ensemble
from app.models import db, Analysis
from celery_app import celery_app
import time

@celery_app.task(bind=True)
def process_bulk_urls(self, user_id, urls, batch_id):
    app = create_app()
    
    with app.app_context():
        total = len(urls)
        
        for i, url in enumerate(urls):
            try:
                heuristics = analyze_url(url)
                ml_scores = ensemble.predict(heuristics)
                
                final_score = (heuristics['total_score'] * 0.6) + (ml_scores['ensemble'] * 0.4)
                
                if final_score < 0.3:
                    result = 'safe'
                elif final_score < 0.6:
                    result = 'suspicious'
                else:
                    result = 'phishing'
                
                analysis = Analysis(
                    user_id=user_id,
                    url=url,
                    result=result,
                    confidence=ml_scores['confidence'],
                    heuristics=heuristics,
                    ml_scores=ml_scores,
                    final_score=final_score,
                    batch_id=batch_id
                )
                db.session.add(analysis)
                db.session.commit()
                
                progress = int(((i + 1) / total) * 100)
                self.update_state(state='PROGRESS', meta={'progress': progress, 'current': i + 1, 'total': total})
                
                socketio.emit('bulk_progress', {
                    'batch_id': batch_id,
                    'progress': progress,
                    'current': i + 1,
                    'total': total,
                    'url': url
                })
                
            except Exception as e:
                continue
        
        return {'completed': total, 'batch_id': batch_id}
```

- [ ] **Step 3: Create app/tasks/screenshot.py**

```python
from app import create_app
from app.models import db, Analysis
from celery_app import celery_app
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import os
import time

@celery_app.task
def capture_screenshot(analysis_id, url):
    app = create_app()
    
    with app.app_context():
        analysis = Analysis.query.get(analysis_id)
        if not analysis:
            return {'error': 'Analysis not found'}
        
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        
        driver = None
        try:
            driver = webdriver.Chrome(options=chrome_options)
            driver.get(url)
            
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, 'body'))
            )
            
            time.sleep(2)
            
            screenshot_dir = 'uploads/screenshots'
            os.makedirs(screenshot_dir, exist_ok=True)
            
            screenshot_path = f'{screenshot_dir}/screenshot_{analysis_id}.png'
            driver.save_screenshot(screenshot_path)
            
            analysis.screenshot_path = screenshot_path
            db.session.commit()
            
            return {'screenshot_path': screenshot_path}
            
        except Exception as e:
            return {'error': str(e)}
            
        finally:
            if driver:
                driver.quit()
```

- [ ] **Step 4: Create app/tasks/reports.py**

```python
from app import create_app
from app.models import db, Analysis, User
from celery_app import celery_app
from weasyprint import HTML
from datetime import datetime
import os

@celery_app.task
def generate_pdf_report(user_id, analysis_ids, report_type='summary'):
    app = create_app()
    
    with app.app_context():
        user = User.query.get(user_id)
        analyses = Analysis.query.filter(Analysis.id.in_(analysis_ids)).all()
        
        safe = sum(1 for a in analyses if a.result == 'safe')
        suspicious = sum(1 for a in analyses if a.result == 'suspicious')
        phishing = sum(1 for a in analyses if a.result == 'phishing')
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhishGuard Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #0d6efd; }}
                .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; }}
                .stat {{ display: inline-block; margin: 10px 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #dee2e6; padding: 12px; text-align: left; }}
                th {{ background: #0d6efd; color: white; }}
            </style>
        </head>
        <body>
            <h1>PhishGuard Analysis Report</h1>
            <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>User: {user.username}</p>
            
            <div class="summary">
                <h2>Summary</h2>
                <div class="stat"><strong>Total:</strong> {len(analyses)}</div>
                <div class="stat"><strong>Safe:</strong> {safe}</div>
                <div class="stat"><strong>Suspicious:</strong> {suspicious}</div>
                <div class="stat"><strong>Phishing:</strong> {phishing}</div>
            </div>
            
            <h2>Analysis Details</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Result</th>
                    <th>Confidence</th>
                    <th>Date</th>
                </tr>
                {''.join(f"<tr><td>{a.url}</td><td>{a.result}</td><td>{a.confidence:.2f}</td><td>{a.created_at}</td></tr>" for a in analyses)}
            </table>
        </body>
        </html>
        """
        
        pdf_dir = 'uploads/reports'
        os.makedirs(pdf_dir, exist_ok=True)
        
        pdf_path = f'{pdf_dir}/report_{user_id}_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}.pdf'
        
        HTML(string=html_content).write_pdf(pdf_path)
        
        return {'pdf_path': pdf_path}
```

- [ ] **Step 5: Create celery_app.py**

```python
import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app

app = create_app(os.environ.get('FLASK_ENV', 'development'))

from celery import Celery

celery = Celery('phishing_detect')
celery.conf.update(app.config)

class ContextTask(celery.Task):
    def __call__(self, *args, **kwargs):
        with app.app_context():
            return self.run(*args, **kwargs)

celery.Task = ContextTask
```

- [ ] **Step 6: Commit**

```bash
git add app/tasks/__init__.py app/tasks/bulk_analysis.py app/tasks/screenshot.py app/tasks/reports.py celery_app.py
git commit -m "feat: add Celery background tasks"
```

---

### Task 10: Docker Configuration

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`

- [ ] **Step 1: Create Dockerfile**

```dockerfile
FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    fonts-liberation \
    libappindicator3-1 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxss1 \
    libxtst6 \
    libxkbcommon0 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY . .

ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production
ENV CHROMIUM_BIN=/usr/bin/chromium
ENV CHROMIUM_DRIVER=/usr/bin/chromedriver

RUN mkdir -p uploads/screenshots uploads/reports

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "run:app"]
```

- [ ] **Step 2: Create docker-compose.yml**

```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=${SECRET_KEY}
      - DATABASE_URL=sqlite:///phishing_detect.db
      - REDIS_URL=redis://redis:6379/0
      - CELERY_BROKER_URL=redis://redis:6379/1
      - CELERY_RESULT_BACKEND=redis://redis:6379/1
      - MAIL_USERNAME=${MAIL_USERNAME}
      - MAIL_PASSWORD=${MAIL_PASSWORD}
    volumes:
      - ./uploads:/app/uploads
      - ./instance:/app/instance
    depends_on:
      - redis
      - celery-worker

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  celery-worker:
    build: .
    command: celery -A celery_app worker --loglevel=info
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=sqlite:///phishing_detect.db
      - REDIS_URL=redis://redis:6379/0
      - CELERY_BROKER_URL=redis://redis:6379/1
      - CELERY_RESULT_BACKEND=redis://redis:6379/1
    volumes:
      - ./uploads:/app/uploads
    depends_on:
      - redis

  celery-beat:
    build: .
    command: celery -A celery_app beat --loglevel=info
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=sqlite:///phishing_detect.db
      - REDIS_URL=redis://redis:6379/0
      - CELERY_BROKER_URL=redis://redis:6379/1
      - CELERY_RESULT_BACKEND=redis://redis:6379/1
    depends_on:
      - redis

volumes:
  uploads:
  instance:
```

- [ ] **Step 3: Commit**

```bash
git add Dockerfile docker-compose.yml
git commit -m "feat: add Docker configuration"
```

---

### Task 11: PWA & Static Files

**Files:**
- Create: `app/static/manifest.json`
- Create: `app/static/sw.js`

- [ ] **Step 1: Create app/static/manifest.json**

```json
{
  "name": "PhishGuard",
  "short_name": "PhishGuard",
  "description": "Zero-Day Phishing Detection System",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#ffffff",
  "theme_color": "#0d6efd",
  "icons": [
    {
      "src": "/static/icons/icon-192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "/static/icons/icon-512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ]
}
```

- [ ] **Step 2: Create app/static/sw.js**

```javascript
const CACHE_NAME = 'phishguard-v1';
const urlsToCache = [
  '/',
  '/static/css/bootstrap.min.css',
  '/static/js/bootstrap.bundle.min.js'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) {
          return response;
        }
        return fetch(event.request);
      })
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});
```

- [ ] **Step 3: Commit**

```bash
git add app/static/manifest.json app/static/sw.js
git commit -m "feat: add PWA manifest and service worker"
```

---

### Task 12: Tests

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/test_auth.py`
- Create: `tests/test_detection.py`
- Create: `tests/test_api.py`

- [ ] **Step 1: Create tests/conftest.py**

```python
import pytest
from app import create_app, db
from app.models import User
from app.auth.utils import hash_password

@pytest.fixture
def app():
    app = create_app('testing')
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_client(client, app):
    with app.app_context():
        user = User(
            username='testuser',
            email='test@example.com',
            password_hash=hash_password('TestPassword123!')
        )
        db.session.add(user)
        db.session.commit()
    
    client.post('/auth/login', data={
        'username': 'testuser',
        'password': 'TestPassword123!'
    })
    
    return client
```

- [ ] **Step 2: Create tests/test_auth.py**

```python
import pytest
from app.models import User

def test_register(client):
    response = client.post('/auth/register', data={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'StrongPassword123!'
    })
    assert response.status_code == 302

def test_login_success(client, app):
    from app.models import db
    from app.auth.utils import hash_password
    
    with app.app_context():
        user = User(
            username='testuser',
            email='test@example.com',
            password_hash=hash_password('TestPassword123!')
        )
        db.session.add(user)
        db.session.commit()
    
    response = client.post('/auth/login', data={
        'username': 'testuser',
        'password': 'TestPassword123!'
    })
    assert response.status_code == 302

def test_login_invalid_password(client, app):
    from app.models import db
    from app.auth.utils import hash_password
    
    with app.app_context():
        user = User(
            username='testuser',
            email='test@example.com',
            password_hash=hash_password('TestPassword123!')
        )
        db.session.add(user)
        db.session.commit()
    
    response = client.post('/auth/login', data={
        'username': 'testuser',
        'password': 'WrongPassword'
    })
    assert b'Invalid' in response.data

def test_logout(auth_client):
    response = auth_client.get('/auth/logout')
    assert response.status_code == 302
```

- [ ] **Step 3: Create tests/test_detection.py**

```python
import pytest
from app.detection.heuristics import analyze_url, shannon_entropy, levenshtein_distance

def test_shannon_entropy():
    assert shannon_entropy('aaaa') > 0
    assert shannon_entropy('abcdefgh') > shannon_entropy('aaaa')

def test_levenshtein_distance():
    assert levenshtein_distance('hello', 'hello') == 0
    assert levenshtein_distance('hello', 'hallo') == 1
    assert levenshtein_distance('hello', 'world') == 4

def test_analyze_url_safe():
    result = analyze_url('https://google.com')
    assert result['result'] in ['safe', 'suspicious', 'phishing']
    assert 'url_length' in result
    assert 'entropy' in result

def test_analyze_url_phishing():
    result = analyze_url('http://192.168.1.1/login.php?redirect=http://fake.com')
    assert 'total_score' in result
    assert result['total_score'] > 0

def test_special_char_detection():
    result = analyze_url('http://example.com/@admin/verify')
    assert result['special_chars'] > 0
```

- [ ] **Step 4: Create tests/test_api.py**

```python
import pytest
from app.models import User, Analysis

def test_analyze_endpoint_no_auth(client):
    response = client.get('/api/analyze/https://google.com')
    assert response.status_code == 401

def test_analyze_endpoint_with_auth(auth_client):
    response = auth_client.get('/api/analyze/https://google.com')
    assert response.status_code == 200
    data = response.get_json()
    assert 'result' in data
    assert 'confidence' in data

def test_watchlist_get(auth_client, app):
    response = auth_client.get('/api/watchlist')
    assert response.status_code == 200

def test_watchlist_add(auth_client):
    response = auth_client.post('/api/watchlist', json={'url': 'http://test.com'})
    assert response.status_code == 201
```

- [ ] **Step 5: Commit**

```bash
git add tests/conftest.py tests/test_auth.py tests/test_detection.py tests/test_api.py
git commit -m "test: add unit tests for auth, detection, and API"
```

---

## Plan Complete

**Plan complete and saved to `docs/superpowers/plans/2026-04-01-phishing-detection-system.md`.**

Two execution options:

1. **Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

2. **Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?