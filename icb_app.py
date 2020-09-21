# from flask import Flask, render_template
# from flask_sqlalchemy import SQLAlchemy
# from datetime import datetime
# app=Flask(__name__)

# app.config['SALALCEMY_DATABASE_URI'] = 'sqlite:///site.db'

# db = SQLAlchemy(app)

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(20), unique=True, nullable=False)
#     password = db.Column(db.String(60), nullable=False)
#     created = db.Column(db.DateTime, nullable=False, default=datatime.utcnow)
    
#     def __repr__(self):
#         return f"User('{self.name}')"

# @app.route('/')
# def hello_world():
#     return 'Hello, wsWorld!'
#     # return render_template('')

# if __name__ == "__main__":
#     app.run(debug=True)

#     # set FLASK_APP=icb_app.py