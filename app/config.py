import os
from datetime import timedelta


def _redis_available():
    """Check if Redis is reachable."""
    redis_url = os.environ.get('REDIS_URL') or os.environ.get('CELERY_BROKER_URL')
    if not redis_url:
        return False
    try:
        import redis as _redis
        client = _redis.from_url(redis_url)
        client.ping()
        client.close()
        return True
    except Exception:
        return False


_has_redis = _redis_available()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32))
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///phishing_detect.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    REDIS_URL = os.environ.get('REDIS_URL', '')

    if _has_redis:
        CACHE_TYPE = 'RedisCache'
        CACHE_REDIS_URL = os.environ.get('REDIS_URL')
        RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL')
        CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', os.environ.get('REDIS_URL'))
        CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', os.environ.get('REDIS_URL'))
    else:
        CACHE_TYPE = 'SimpleCache'
        RATELIMIT_STORAGE_URI = 'memory://'
        CELERY_BROKER_URL = ''
        CELERY_RESULT_BACKEND = ''
        CELERY_ALWAYS_EAGER = True
        CELERY_EAGER_PROPAGATES = True

    CACHE_DEFAULT_TIMEOUT = 86400

    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    RATELIMIT_DEFAULT = "100 per hour"

    API_RATE_LIMIT = "10 per minute"
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

    SELENIUM_HEADLESS = os.environ.get('SELENIUM_HEADLESS', 'true').lower() == 'true'

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'csv'}


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    DEBUG = False


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}