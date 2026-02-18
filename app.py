import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template
from extensions import db, login_manager
from flask_migrate import Migrate
from flask_mail import Mail
from config import Config

mail = Mail()
migrate = Migrate()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Bitte melde dich an, um diese Seite zu sehen.'
    login_manager.login_message_category = 'info'

    from models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Angelwettbewerb Start')

    from routes.main import main_bp
    from routes.auth import auth_bp
    from routes.user import user_bp
    from routes.admin import admin_bp
    from routes.competition import comp_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(comp_bp)

    @app.context_processor
    def utility_processor():
        try:
            from utils.context_processors import get_social_links
            return dict(get_social_links=get_social_links)
        except:
            return dict(get_social_links=lambda: [])

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    return app

app = create_app()

with app.app_context():
    from models import db, User
    db.create_all()
    print("✅ Таблицы БД проверены/созданы.")
    if User.query.count() == 0:
        from seed import seed_data
        seed_data()
        print("✅ Seed-Daten eingefügt.")

if __name__ == '__main__':
    app.run()
