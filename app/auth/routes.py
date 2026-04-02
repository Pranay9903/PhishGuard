from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
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

        if len(username) < 4:
            flash('Username must be at least 4 characters long', 'danger')
            return render_template('auth/register.html')

        if not re.search(r'[a-zA-Z]', username) or not re.search(r'[0-9]', username):
            flash('Username must contain at least one letter and one number', 'danger')
            return render_template('auth/register.html')

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
        
        log = AuditLog(
            user_id=current_user.id,
            event_type='password_change',
            details='Password changed - all sessions invalidated',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
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

@auth_bp.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('password')
    
    if not verify_password(password, current_user.password_hash):
        flash('Incorrect password. Account not deleted.', 'danger')
        return redirect(url_for('main.settings'))
    
    user_id = current_user.id
    username = current_user.username
    
    AuditLog.query.filter_by(user_id=user_id).delete()
    from app.models import Analysis, Watchlist, Feedback
    Analysis.query.filter_by(user_id=user_id).delete()
    Watchlist.query.filter_by(user_id=user_id).delete()
    Feedback.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(current_user)
    db.session.commit()
    
    logout_user()
    flash('Your account has been permanently deleted.', 'info')
    return redirect(url_for('main.index'))