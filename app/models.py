from app.extensions import db
from flask_login import UserMixin
from datetime import datetime
import secrets
import pyotp

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    api_key = db.Column(db.String(64), unique=True, nullable=True)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=True)
    
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
    result = db.Column(db.String(20), nullable=False)
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
    status = db.Column(db.String(20), default='pending')
    last_checked = db.Column(db.DateTime, nullable=True)
    notify_on_change = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis.id'), nullable=False)
    feedback_type = db.Column(db.String(10), nullable=False)
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