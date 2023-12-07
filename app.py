from flask import Flask, render_template, request, redirect, abort, session, url_for
from flask_bcrypt import Bcrypt
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
from dotenv import load_dotenv
from os import getenv
from src.models import db, User
import os 
import requests
import base64
import datetime
import threading
import uuid 
import queue

app = Flask(__name__)

contact_storage = []

load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{os.getenv("db_user")}:{os.getenv("db_password")}@{os.getenv("db_host")}:{os.getenv("db_port")}/{os.getenv("db_name")}'
app.secret_key = getenv('FLASK_SECRET_KEY')
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
    return render_template('signup.html')

@app.get('/discussion_page')
def discussion_page():
    return render_template('discussion.html')

@app.route('/contact_page')
def contact_page():
    return render_template('contact.html')

@app.route('/profile_page')
def profile_page():
    return render_template('profile.html')

@app.route('/get_user_playlists')
def get_user_playlists():
    if 'access_token' not in session and 'refresh_token' not in session:
        abort(403, 'Not authorized with Spotify, please connect to continue')

    try:
        if session['playlists'] == True:
            return redirect(url_for('playlist', playlist_id = list(cache.keys())[0].split(', ')[1]))
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
            return redirect(url_for('playlist', playlist_id = unique_playlist_id))
        else:
            data = get_response.json()
            unique_playlist_id = get_information(data)
            session['playlists'] = True
            return redirect(url_for('playlist', playlist_id = unique_playlist_id))

@app.get('/playlist/<playlist_id>')
def playlist(playlist_id):

    logged_in = 'email' in list(session.keys())

    id_list = []
    for key in list(cache.keys()):
        id_list.append(key.split(', ')[1])

    if playlist_id not in id_list:
        return redirect(url_for('discussion_page'))
    else:
        playlist_data = cache[f'{session["email"]}, {playlist_id}']
        user_playlist = spotify.playlist(playlist_id = playlist_data[-1])
        owner = user_playlist['owner']['display_name']
        unique_artists = set(playlist_data[3])
        names = []
        for key in list(cache.keys()):
            if key.split(', ')[0] == session['email']:
                names.append((cache[key][0], key.split(', ')[1]))
        return render_template('playlist.html', 
                               playlist_data = playlist_data, 
                               names = names, 
                               owner = owner, 
                               unique_artists = unique_artists,
                               logged_in = logged_in)

@app.route('/account_settings_page')
def account_settings_page():
    return render_template('account_settings.html')

@app.route('/account_contact_page')
def account_contact_page():
    return render_template('account_contact.html')

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

    return render_template('success.html')

@app.get('/authorize_url')
def authorize_spotify_url():
    return redirect(spotify_auth.get_authorize_url())

# Functions for functionality

@app.post('/sign_up_page')
def sign_up():

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

    new_user = User(username=username, password=hashed_password, first_name=first_name, last_name=last_name, email=email)
        
    db.session.add(new_user)
    db.session.commit()
    
    session['email'] = email
    session['playlists'] = False 

    if spotify_allowed:
        return redirect(spotify_auth.get_authorize_url())
    else:
        return redirect('/')

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
    session['playlists'] = False

    if user_exists.spotify_refresh_token != None:
        session['refresh_token'] = user_exists.spotify_refresh_token
        
    return redirect('profile_page')

@app.post('/profile_info')
def profile_info():
    # get data here when more functionality is established 
    return redirect('account_settings.html')

@app.post('/send_contact')
def send_contact():
    # get data here when more functionality is established 
    return redirect('account_contact.html')


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

        thread = threading.Thread(target = get_playlist_information, args = (playlist_id, playlist_name, session['email']))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
        
    return Queue.get()

def get_playlist_information(playlist_id, playlist_name, email) -> []:

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
    cache[f'{email}, {unique_playlist_id}'] = [playlist_name, track_names, track_albums, track_artists, track_durations, playlist_id]

    Queue.put(unique_playlist_id)
