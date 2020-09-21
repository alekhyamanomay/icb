from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_material import Material

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'secret-key-goes-here'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://Manomay1:manomay1@DESKTOP-IRHNO1M\SQLEXPRESS/ICB_db?driver=SQL Server?Trusted_Connection=No'

    db.init_app(app)

    Material(app)
    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    # from .main import main as main_blueprint
    # app.register_blueprint(main_blueprint)

    return app

if __name__ == '__main__':
    app.run(debug=True)