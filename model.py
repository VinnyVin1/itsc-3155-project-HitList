from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True , autoincrement=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)


def __init__(self, id, title, content):
    self.id = id
    self.title = title
    self.content = content

def __repr__(self):
    return f'<Post {self.id, self.title, self.content}>'