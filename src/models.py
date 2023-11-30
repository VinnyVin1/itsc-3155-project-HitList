from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):

    __tablename__ = 'User'

    user_id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(255), nullable = False)
    password = db.Column(db.String(255), nullable = False)
    first_name = db.Column(db.String(255), nullable = False)
    last_name = db.Column(db.String(255), nullable = False)
    email = db.Column(db.String(255), nullable = False, unique = True)
    spotify_refresh_token = db.Column(db.String(512), nullable = True)

    def __init__(self, username: str, password: str, first_name: str, last_name: str, email: str) -> None:
        self.username = username
        self.password = password 
        self.first_name = first_name
        self.last_name = last_name
        self.email = email