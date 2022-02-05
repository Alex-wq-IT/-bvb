from flask import Flask
from os import path
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
DB_NAME = 'test2.db'

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'fgrt dhnty'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    from .userss import userss
    app.register_blueprint(userss, url_prefix='/')

    from .baze import User

    create_database(app)


    login_manager = LoginManager()
    login_manager.login_view ='userss.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))
    return app

def create_database(app):
    if not path.exists('website2/' + DB_NAME):
        db.create_all(app=app)
        print('Created database!')
