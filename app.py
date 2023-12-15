from flask import Flask, render_template, request, redirect, abort, session, url_for
from flask_bcrypt import Bcrypt
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
from dotenv import load_dotenv
from os import getenv
from src.models import db, User, Posts, Comment 
import requests
import base64
import datetime
import threading
import uuid 
import queue

app = Flask(__name__)

contact_storage = []

load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{getenv("db_user")}:{getenv("db_password")}@{getenv("db_host")}:{getenv("db_port")}/{getenv("db_name")}'
app.secret_key = getenv('FLASK_SECRET_KEY')
print("You are running in " + app.secret_key)
db.init_app(app)
bcrypt = Bcrypt(app)

spotify = spotipy.Spotify(client_credentials_manager = SpotifyClientCredentials())

spotify_auth = spotipy.SpotifyOAuth(
    client_id = getenv('SPOTIPY_CLIENT_ID'),
    client_secret= getenv('SPOTIPY_CLIENT_SECRET'),
    redirect_uri = getenv('SPOTIPY_REDIRECT_URI'),
    scope = 'user-library-read user-read-currently-playing streaming'
)

Queue = queue.Queue()
cache = dict()

# Functions to get pages

@app.get('/')
def index_page():
    return render_template('index.html')

@app.get('/signin_page')
def signin_page():
    if 'email' in session:
        return redirect('discussion_page')
    return render_template('signin.html')

@app.get('/signup_page')
def signup_page():
    if session:
        return redirect(url_for('discussion_page'))
    return render_template('signup.html')

@app.route('/discussion_page')
def discussion_page():
    date = datetime.datetime.now()
    user = None

    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()

    post_list = Posts.query.all()
    post_list_with_images = []

    for post in post_list:
        post_user = User.query.filter_by(username=post.user_name).first()
        if post_user and post_user.profile_image:
            post_list_with_images.append([base64.b64encode(post_user.profile_image).decode("utf-8"), post])
        else:
            post_list_with_images.append([None, post])

    user_profile_image = None
    if user and user.profile_image:
        user_profile_image = base64.b64encode(user.profile_image).decode('utf-8')

    return render_template('discussion.html', 
                           display_name=session.get('display_name'), 
                           username=session.get('username'), 
                           date=date.strftime("%d %B %Y"), 
                           post_list=post_list_with_images, 
                           user_profile_image=user_profile_image)

@app.post('/discussion_page')
def createdPost():
    if request.method == 'POST':
        new_post =  Posts(title = request.form.get('title'), created = datetime.datetime.now(), user_name = session['username'], content = request.form.get('content'))
        db.session.add(new_post)
        db.session.commit()
        date = datetime.datetime.now()
        post_list = Posts.query.all()
    return redirect(url_for('discussion_page', display_name = session['display_name'], username = session['username'], date = date.strftime("%d %B %Y"), post_list = post_list))

@app.get('/post/<id>')
def get_post_by_id(id):
    post = Posts.query.filter_by(id = id).first()
    if post == None:
        abort(404, 'Post not found with specified ID')
    user = 'email' in session
    post_comments = Comment.query.filter_by(post_id = id).all()
    if not post_comments:
        return render_template('post.html', post = post, user = user)
    return render_template('post.html', post = post, comments = post_comments, user = user)

@app.post('/post/<id>')
def create_comment(id):
    if request.form['submit-btn'] == 'comment':
        content = request.form.get('content')
        created = datetime.datetime.now()
        user_name = session['username']
        commet = Comment(created = created, user_name = user_name, content = content, id = id)
        db.session.add(commet)
        db.session.commit()
        return redirect(url_for('get_post_by_id', id = id))
    elif request.form['submit-btn'] == 'delete':
        comment = Comment.query.filter_by(comment_id = request.form['comment_id']).first()
        db.session.delete(comment)
        db.session.commit()
        return redirect(url_for('get_post_by_id', id = id))
    elif request.form['submit-btn'] == 'edit':
        return redirect(url_for('edit_comment', id = request.form['comment_id']))
    elif request.form['submit-btn'] == 'delete-post-btn':
        post = Posts.query.filter_by(id = id).first()
        post_comments = Comment.query.filter_by(post_id = id).first()
        db.session.delete(post_comments)
        db.session.commit()
        db.session.delete(post)
        db.session.commit()
        return redirect(url_for('discussion_page'))
    elif request.form['submit-btn'] == 'edit-post-btn':
        return redirect(url_for('get_edit_post', id = id ))

@app.get('/post/edit/<id>')
def get_edit_post(id):
    post = Posts.query.filter_by(id = id).first()
    if not session['username'] or session['username'] != post.user_name:
        abort(403, 'This is not your post!')
    return render_template('post_edit.html', post = post)

@app.post('/post/edit/<id>')
def edit_post(id):
    post = Posts.query.filter_by(id = id).first()
    new_title = request.form.get('title')
    new_content = request.form.get('content')
    post.title = new_title
    post.content = new_content
    db.session.add(post)
    db.session.commit()
    return redirect(url_for('get_post_by_id', id = post.id))

@app.get('/comment/edit/<id>')
def edit_comment(id):
    comment = Comment.query.filter_by(comment_id = id).first()
    if not session['username'] or session['username'] != comment.user_name:
        abort(403, 'This isnt your comment!')
    return render_template('comment_edit.html', comment = comment)

@app.post('/comment/edit/<id>')
def new_comment(id):
    comment = Comment.query.filter_by(comment_id = id).first()
    content = request.form.get('content')
    comment.content = content 
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('get_post_by_id', id = comment.post_id))

@app.route('/contact_page')
def contact_page():
    return render_template('contact.html')

@app.get('/profile/<username>')
def profile_page(username):
    user = User.query.filter_by(username = username).first_or_404('Username not found, please check spelling and try again')
    is_user = True
    user_has_playlists = False
    for key in list(cache.keys()):
        if key.split(', ')[0] == user.username:
            user_has_playlists = True
            break

    user_posts = Posts.query.filter_by(user_name = user.username).all()
    user_profile_image = None
    if user.profile_image != None:
        user_profile_image = base64.b64encode(user.profile_image).decode('utf-8')
    if not session or session['username'] != user.username:
        return render_template('profile.html', display_name = user.display_name, user_id = user.user_id, username = username, is_user = False, user_posts = user_posts, user_has_playlists = user_has_playlists, user_profile_image = user_profile_image)
    return render_template('profile.html', display_name = user.display_name, user_id = user.user_id, username = username, is_user = True, user_posts = user_posts, user_has_playlists = user_has_playlists, user_profile_image = user_profile_image)

@app.route('/get_user_playlists')
def get_user_playlists():
    if 'access_token' not in session and 'refresh_token' not in session:
        abort(403, 'Not authorized with Spotify, please connect to continue')
    usernames = []
    playlist_id = ''
    for index, key in enumerate(list(cache.keys())):
        usernames.append(key.split(', ')[0])
        if key.split(', ')[0] == session['username']:
           playlist_id = key.split(', ')[1]

    try:
        if session['playlists'] == True and session['username'] in usernames:
            return redirect(url_for('playlist', playlist_id = playlist_id))
    except IndexError:
        session['playlists'] = False
        return redirect('get_user_playlists')
    
    access_code = session.get('access_token')

    if 'email' not in session:
        return redirect('signin_page')

    else:
        header = {
            'Authorization': f'Bearer {access_code}'
        }
        get_response = requests.get("https://api.spotify.com/v1/me/playlists", headers = header)
        
        if get_response.status_code == 401:
            new_token = get_new_access_token()
            secondary_header = {
                'Authorization': f'Bearer {new_token}'
            }
            secondary_response = requests.get("https://api.spotify.com/v1/me/playlists", headers = secondary_header)
            secondary_data = secondary_response.json()
            unique_playlist_id = get_information(secondary_data)
            session['playlists'] = True
            return redirect(url_for('get_playlists_by_user', username = session['username']))
        else:
            data = get_response.json()
            unique_playlist_id = get_information(data)
            session['playlists'] = True
            return redirect(url_for('get_playlists_by_user', username = session['username']))

@app.route('/authorize_spotify')
def authorize_spotify():
    if 'email' not in session:
        return redirect(url_for('signin_page'))
    
    return redirect(spotify_auth.get_authorize_url())

@app.get('/playlist/<playlist_id>')
def playlist(playlist_id):
    logged_in = False
    if session:
        logged_in = True

    id_list = []
    username = ''
    for key in list(cache.keys()):
        id_list.append(key.split(', ')[1])

    if playlist_id not in id_list:
        return redirect(url_for('discussion_page'))
    else:

        for key in list(cache.keys()):
            if key.split(', ')[1] == playlist_id:
                username = key.split(', ')[0]
        playlist_data = cache[f'{username}, {playlist_id}']
        user_playlist = spotify.playlist(playlist_id = playlist_data[-1])
        owner = user_playlist['owner']['display_name']
        unique_artists = set(playlist_data[3])

        names = []
        if session:
            for key in list(cache.keys()):
                if key.split(', ')[0] == session['username']:
                    names.append((cache[key][0], key.split(', ')[1]))
        
        user = User.query.filter_by(username = username).first()
        user_profile_image = None 
        if user.profile_image != None:
            user_profile_image = base64.b64encode(user.profile_image).decode('utf-8')

        return render_template('playlist.html', 
                               playlist_data = playlist_data, 
                               names = names, 
                               owner = owner, 
                               unique_artists = unique_artists,
                               logged_in = logged_in,
                               username = username,
                               user_profile_image = user_profile_image)
    
@app.get('/playlists/<username>')
def get_playlists_by_user(username):
    user = User.query.filter_by(username = username).first()
    user_profile_image = None 
    if user.profile_image != None:
        user_profile_image = base64.b64encode(user.profile_image).decode('utf-8')
    user_playlist_data = {}
    playlist_data = {}
    current_cache_username = ''
    for key, value in cache.items():
        current_cache_username= str(key).split(', ')[0]
        if username == current_cache_username:
            user_playlist_data[str(key).split(', ')[1]] = value

    return render_template('playlist.html', user_playlist_data = user_playlist_data, playlist_data = playlist_data, user_profile_image = user_profile_image)
        
@app.route('/account_settings_page')
def account_settings_page():
    if not session:
        return redirect(url_for('signin_page'))
    user = User.query.filter_by(username = session['username']).first()
    user_profile_image = None
    if user.profile_image != None:
        user_profile_image = base64.b64encode(user.profile_image).decode('utf-8')
    first_name = user.first_name
    last_name = user.last_name
    email = user.email
    username = user.username
    display_name = user.display_name
    return render_template('account_settings.html', username = username, user_id = user.user_id, email = email, first_name = first_name, last_name = last_name, display_name = display_name, user_profile_image = user_profile_image)

@app.route('/account_contact_page')
def account_contact_page():
    user = User.query.filter_by(username = session['username']).first()
    username = user.username
    user_profile_image = None
    if user.profile_image != None:
        user_profile_image = base64.b64encode(user.profile_image).decode('utf-8')
    return render_template('account_contact.html', username = username, user_id = user.user_id, user_profile_image = user_profile_image)

def store_message_in_file(message):
    with open('contact_messages.txt', 'a') as file:
        file.write(message + '\n')

@app.route('/contact_us', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        message = request.form['message']

        contact_storage.append({
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'message': message
        })

        store_message_in_file(f"Name: {first_name} {last_name}, Email: {email}, Message: {message}")

        return render_template('contact_success.html', first_name=first_name)

    return render_template('contact.html')

@app.get('/success_page')
def success_page():
    auth_token = request.args.get('code')
    email = session['email']

    if not email:
        return redirect('signin_page')
    
    user = User.query.filter_by(email = email).first()
    header = base64.b64encode(f"{getenv('SPOTIPY_CLIENT_ID')}:{getenv('SPOTIPY_CLIENT_SECRET')}".encode("utf-8")).decode("utf-8")

    request_access_code = {
        'grant_type': 'authorization_code',
        'code': auth_token,
        'redirect_uri': getenv('SPOTIPY_REDIRECT_URI')
    }

    data_response = requests.post('https://accounts.spotify.com/api/token', data=request_access_code, headers={'Authorization': f'Basic {header}'})
    data = data_response.json()

    user.spotify_refresh_token = data['refresh_token']
    db.session.add(user)
    db.session.commit()

    session['access_token'] = data['access_token']
    session['refresh_token'] = data['refresh_token']

    return render_template('success.html', username=session.get('username'))

@app.post('/sign_up_page')
def sign_up():
    display_name = request.form.get('display_name')
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email = request.form.get('email')
    username = request.form.get('username')
    raw_password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    spotify_allowed = request.form.get('auth')

    if not first_name or not last_name or not email or not username or not confirm_password:
        abort(400, "Entered bad information into form")

    if User.query.filter_by(email = email).first():
        abort(400, 'Email already in use')

    hashed_password = bcrypt.generate_password_hash(raw_password, 10).decode()

    new_user = User(display_name = display_name, username=username, password=hashed_password, first_name=first_name, last_name=last_name, email=email, profile_image = None)
        
    db.session.add(new_user)
    db.session.commit()
    
    session['email'] = email
    session['username'] = username
    session['display_name'] = display_name
    session['playlists'] = False 

    if spotify_allowed:
        return redirect(spotify_auth.get_authorize_url())
    else:
        return redirect(url_for('profile_page', username=username))

@app.post('/signin_page')
def sign_in():
    # if user is logged in redirect them to discussion page
    if 'email' in session:
        return redirect('discussion_page')

    email = request.form.get('email')
    raw_password = request.form.get('password')
    user_exists = User.query.filter_by(email = email).first()

    if not bcrypt.check_password_hash(user_exists.password, raw_password):
        abort(401)

    session['email'] = email
    session['username'] = user_exists.username
    session['playlists'] = False
    session['display_name'] = user_exists.display_name

    if user_exists.spotify_refresh_token != None:
        session['refresh_token'] = user_exists.spotify_refresh_token
        
    return redirect(f'/profile/{user_exists.username}')

@app.post('/profile/<username>')
def upload_profile_image(username):
    user = User.query.filter_by(username = username).first()
    image = request.files['file'].read()
    user.profile_image = image
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('profile_page', username = username))

@app.post('/send_contact')
def send_contact():
    # get data here when more functionality is established 
    return redirect('account_contact.html')

@app.post('/account_settings_page')
def change_account_settings():
    user = User.query.filter_by(username = session['username']).first()
    if request.form['submit-btn'] == 'change_first_name':
        user.first_name = request.form.get('first_name')
        db.session.add(user)
        db.session.commit()
    elif request.form['submit-btn'] == 'change_last_name':
        user.last_name = request.form.get('last_name')
        db.session.add(user)
        db.session.commit()
    elif request.form['submit-btn'] == 'change_username':
        user_posts = Posts.query.filter_by(user_name = session['username']).all()
        for post in user_posts:
            post.user_name = request.form.get('username')
            db.session.add(post)
            db.session.commit()
        user.username = request.form.get('username')
        session['username'] = user.username
        db.session.add(user)
        db.session.commit()
    elif request.form['submit-btn'] == 'change_display_name':
        user.display_name = request.form.get('display_name')
        session['display_name'] = user.display_name
        db.session.add(user)
        db.session.commit()
    elif request.form['submit-btn'] == 'change_email':
        user.email = request.form.get('email')
        session['email'] = request.form.get('email')
        db.session.add(user)
        db.session.commit()
    elif request.form['submit-btn'] == 'change_password':
        raw_password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(raw_password, 10).decode()
        user.password = hashed_password
        db.session.add(user)
        db.session.commit()
    elif request.form['submit-btn'] == 'delete-account':
        db.session.delete(user)
        db.session.commit()
        session.clear()
    elif request.form['submit-btn'] == 'logout':
        session.clear()
        return redirect('/')
    elif request.form['submit-btn'] == 'connect-spotify':
        return redirect(spotify_auth.get_authorize_url())

    return redirect('account_settings_page')

# Functions for Spotify API

def get_new_access_token():
    refresh_code = session.get('refresh_token')

    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_code,
        'client_id': getenv('SPOTIPY_CLIENT_ID'),
        'client_secret': getenv('SPOTIPY_CLIENT_SECRET')
    }

    spotify_response = requests.post('https://accounts.spotify.com/api/token', data = data)
    new_data = spotify_response.json()
    new_access_token = new_data.get('access_token')
    session['access_token'] = new_access_token
    session['refresh_token'] = new_data.get('refresh_token')
    return new_access_token

def get_information(data):
    playlists = data['items']
    playlist_uris = [playlist['uri'] for playlist in playlists]
    playlist_names = [playlist['name'] for playlist in playlists]
    
    playlist_id = ''
    playlist_id_list = []

    for playlist_uri in playlist_uris:
        playlist_id = playlist_uri.split(':')[-1]
        playlist_id_list.append(playlist_id)

    threads = []
    for index, playlist_id in enumerate(playlist_id_list):
        playlist_name = playlist_names[index]

        thread = threading.Thread(target = get_playlist_information, args = (playlist_id, playlist_name, session['username']))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
        
    return Queue.get()

def get_playlist_information(playlist_id, playlist_name, username) -> []:

    track_names = []
    track_albums = []
    track_artists = []
    track_durations = []
    date = ''

    playlist = spotify.playlist(playlist_id = playlist_id)
    i = 0
    while i < playlist['tracks']['total']:
        batch = spotify.playlist_tracks(playlist_id = playlist_id, offset = i, limit = 50)
        for playlist_track in batch['items']:
            track_names.append(playlist_track['track']['name'])
            track_albums.append(playlist_track['track']['album']['name'])
            track_artists.append(playlist_track['track']['artists'][0]['name'])
            date = str(datetime.timedelta(milliseconds = playlist_track['track']['duration_ms']))
            date = date.split(':')
            track_durations.append(f'{date[1]}:{date[2][0:2]}')
        
        i += 50

    unique_playlist_id = str(uuid.uuid4())
    cache[f'{username}, {unique_playlist_id}'] = [playlist_name, track_names, track_albums, track_artists, track_durations, playlist_id]

    Queue.put(unique_playlist_id)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    post_to_delete = Posts.query.get_or_404(post_id)
    if post_to_delete.user_name != session['username']:
        abort(403, "You are not authorized to delete this post.")
    
    comment = Comment.query.filter_by(post_id = post_id).delete()
    db.session.delete(post_to_delete)
    db.session.commit()

    return redirect(url_for('profile_page', username=session['username']))
