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