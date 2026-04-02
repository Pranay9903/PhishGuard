from celery import Celery

celery_app = Celery('phishing_detect')

celery_app.config_from_object('app.config:Config', namespace='CELERY')
celery_app.autodiscover_tasks(['app.tasks'])