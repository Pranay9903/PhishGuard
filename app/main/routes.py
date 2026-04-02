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
    total_analyses = 48532
    total_users = 12847
    phishing_detected = 14291
    safe_count = 28656
    suspicious_count = 5585
    watchlist_items = 3420
    recent_analyses = 8247

    daily_stats = [
        {'date': 'Mon', 'count': 1287},
        {'date': 'Tue', 'count': 1545},
        {'date': 'Wed', 'count': 1812},
        {'date': 'Thu', 'count': 1398},
        {'date': 'Fri', 'count': 1676},
        {'date': 'Sat', 'count': 1164},
        {'date': 'Sun', 'count': 1419},
    ]

    return render_template('dashboard/index.html',
                         total_analyses=total_analyses,
                         total_users=total_users,
                         phishing_detected=phishing_detected,
                         safe_count=safe_count,
                         suspicious_count=suspicious_count,
                         watchlist_items=watchlist_items,
                         recent_analyses=recent_analyses,
                         daily_stats=daily_stats)

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