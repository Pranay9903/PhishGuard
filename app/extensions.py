from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_mail import Mail
from flask_migrate import Migrate
from celery import Celery
from flask_socketio import SocketIO

db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(get_remote_address)
cache = Cache()
mail = Mail()
migrate = Migrate()
celery = Celery('phishing_detect')
socketio = SocketIO()
