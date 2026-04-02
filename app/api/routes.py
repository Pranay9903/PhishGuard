from flask import request, jsonify
from flask_restx import Api, Resource, fields
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import login_required, current_user
from app.api import api_bp
from app.models import db, User, Analysis, Watchlist, Feedback, AuditLog
from app.detection.heuristics import analyze_url
from app.detection.ml_ensemble import ensemble
from app.detection.ssl_checker import get_ssl_info
from app.detection.dns_analyzer import analyze_dns, get_whois_info
from app.detection.typosquatting import detect_typosquatting
from app.auth.utils import verify_password
import requests
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
        
        from app import celery_available
        if celery_available():
            from app.tasks.bulk_analysis import process_bulk_urls
            process_bulk_urls.delay(current_user.id, urls, batch_id)
        else:
            from app.tasks.bulk_analysis import process_bulk_urls_sync
            process_bulk_urls_sync(current_user.id, urls, batch_id)
        
        return {'batch_id': batch_id, 'total_urls': len(urls)}

analyses_ns = api.namespace('analyses', description='Analysis Management')

@analyses_ns.route('/all')
class DeleteAllAnalyses(Resource):
    @login_required
    def delete(self):
        Analysis.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return {'message': 'All analyses deleted'}

@analyses_ns.route('')
class DeleteSelectedAnalyses(Resource):
    @login_required
    def delete(self):
        data = request.json
        if not data or 'ids' not in data:
            api.abort(400, 'No IDs provided')
        Analysis.query.filter(
            Analysis.id.in_(data['ids']),
            Analysis.user_id == current_user.id
        ).delete(synchronize_session=False)
        db.session.commit()
        return {'message': f"Deleted {len(data['ids'])} analysis(s)"}

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