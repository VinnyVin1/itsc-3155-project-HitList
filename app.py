from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from .model import db, Posts

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@localhost:5432/HitList_Posts'


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Functions to get pages
@app.get('/')
def index_page():
    return render_template('index.html')

@app.get('/signin_page')
def signin_page():
    return render_template('signin.html')

@app.get('/signup_page')
def signup_page():
    return render_template('signup.html')

@app.get('/discussion_page')
def discussion_page():
    return render_template('discussion.html')

@app.post('/createdPost')
def createdPost():
    title_v = request.form.get('title')
    content_v = request.form.get('content')
    new_post = {title = title_v, 'content': content_v}
    db.session.add(new_post)
    db.session.commit()
    return render_template('discussion.html')

@app.route('/contact_page')
def contact_page():
    return render_template('contact.html')

@app.route('/playlist_page')
def playlist_page():
    return render_template('playlist.html')

@app.route('/account_settings_page')
def account_settings_page():
    return render_template('account_settings.html')

@app.route('/account_contact_page')
def account_contact_page():
    return render_template('account_contact.html')


# Functions for functionality

@app.post('/signin')
def sign_in():
    # get data here when more functionality is established 
    return redirect('index.html')

if __name__ == '__main__':
    db.create_all()