from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):

    __tablename__ = 'User'

    display_name = db.Column(db.String(255), nullable = False)
    user_id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(255), nullable = False)
    password = db.Column(db.String(255), nullable = False)
    first_name = db.Column(db.String(255), nullable = False)
    last_name = db.Column(db.String(255), nullable = False)
    email = db.Column(db.String(255), nullable = False, unique = True)
    spotify_refresh_token = db.Column(db.String(512), nullable = True)

    def __init__(self, display_name: str, username: str, password: str, first_name: str, last_name: str, email: str) -> None:
        self.display_name = display_name
        self.username = username
        self.password = password 
        self.first_name = first_name
        self.last_name = last_name
        self.email = email

class Posts(db.Model):

    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime)
    user_name = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.String(1000), nullable=False)

    def __init__(self, user_name, created, title, content):
        self.created = created
        self.user_name = user_name
        self.title = title
        self.content = content

    def __repr__(self):
        return f'<Post {self.id, self.created, self.user_name, self.title, self.content}>'