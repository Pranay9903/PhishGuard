from flask import Flask
from app.extensions import db, login_manager, limiter, cache, mail, migrate, celery, socketio


def create_app(config_name='default'):
    from app.config import config
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    limiter.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    cache.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    
    celery.conf.update(app.config)
    
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    
    from app.auth.routes import auth_bp
    from app.api.routes import api_bp
    from app.main.routes import main_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(main_bp)
    
    with app.app_context():
        db.create_all()
    
    login_manager.login_view = 'auth.login'
    
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))
    
    return app

def create_celery_app(app=None):
    app = app or create_app()
    celery.conf.update(app.config)
    
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery
