from flask import Flask

from src.config import DB_URL, SECRET_KEY
from src.extensions import db, migrate
from src.main_app import main_app, login_manager


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    app.register_blueprint(main_app)
    return app


if __name__ == '__main__':
    application = create_app()
    application.run(debug=True)