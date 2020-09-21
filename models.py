from . import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    email = db.Column(db.String(50), unique=True, nullable=False) 
    name = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
    
    def __repr__(self):
        return f"User('{self.name}')"
