from app import create_app
from app.models import db, Analysis, User
from datetime import datetime
import os

try:
    from celery_app import celery_app
except Exception:
    celery_app = None


def generate_pdf_report_sync(user_id, analysis_ids, report_type='summary'):
    """Synchronous fallback when Celery/Redis is not available."""
    try:
        from weasyprint import HTML
    except ImportError:
        return {'error': 'WeasyPrint not available'}

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


if celery_app:
    @celery_app.task
    def generate_pdf_report(user_id, analysis_ids, report_type='summary'):
        app = create_app()

        with app.app_context():
            return generate_pdf_report_sync(user_id, analysis_ids, report_type)