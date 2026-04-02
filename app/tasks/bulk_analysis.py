from app import create_app, socketio
from app.detection.heuristics import analyze_url
from app.detection.ml_ensemble import ensemble
from app.models import db, Analysis
import time

try:
    from celery_app import celery_app
except Exception:
    celery_app = None


def process_bulk_urls_sync(user_id, urls, batch_id):
    """Synchronous fallback when Celery/Redis is not available."""
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
            socketio.emit('bulk_progress', {
                'batch_id': batch_id,
                'progress': progress,
                'current': i + 1,
                'total': total,
                'url': url
            })

        except Exception:
            continue

    return {'completed': total, 'batch_id': batch_id}


if celery_app:
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

                except Exception:
                    continue

            return {'completed': total, 'batch_id': batch_id}