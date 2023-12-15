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
    profile_image = db.Column(db.LargeBinary, nullable = True)

    def __init__(self, display_name: str, username: str, password: str, first_name: str, last_name: str, email: str, profile_image: bytes) -> None:
        self.display_name = display_name
        self.username = username
        self.password = password 
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.profile_image = profile_image

class Posts(db.Model):

    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created = db.Column(db.DateTime)
    user_name = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    comments = db.relationship('Comment', backref = 'Post', lazy = True)

    def __init__(self, user_name, created, title, content):
        self.created = created
        self.user_name = user_name
        self.title = title
        self.content = content

    def __repr__(self):
        return f'<Post {self.id, self.created, self.user_name, self.title, self.content}>'

class Comment(db.Model):

    __tablename__ = 'comment'

    comment_id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    created = db.Column(db.DateTime)
    user_name = db.Column(db.String(100), nullable = False)
    content = db.Column(db.String(100), nullable = False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable = False)

    def __init__(self, created, user_name, content, id):
        self.created = created
        self.user_name = user_name
        self.content = content
        self.post_id = id
