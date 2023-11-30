from flask import Flask, render_template, request, redirect, abort, session
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

app = Flask(__name__)

load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{os.getenv("db_user")}:{os.getenv("db_password")}@{os.getenv("db_host")}:{os.getenv("db_port")}/{os.getenv("db_name")}'
app.secret_key = '1234'
db.init_app(app)

bcrypt = Bcrypt(app)

spotify = spotipy.Spotify(client_credentials_manager = SpotifyClientCredentials())

spotify_auth = spotipy.SpotifyOAuth(
    client_id = getenv('SPOTIPY_CLIENT_ID'),
    client_secret= getenv('SPOTIPY_CLIENT_SECRET'),
    redirect_uri = getenv('SPOTIPY_REDIRECT_URI'),
    scope = 'user-library-read user-read-currently-playing streaming'
)

# Functions to get pages

@app.get('/')
def index_page():
    return render_template('index.html')

@app.get('/signin_page')
def signin_page():
    print(session)
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

@app.route('/playlist_page')
def playlist_page():
    access_code = session.get('access_token')

    if not access_code:
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
            
            # Information for each user playlist
            secondary_playlist_data = get_playlist_information(secondary_data)
            print(f'Playlist data is {secondary_playlist_data}')

        else:
            data = get_response.json()

            # Information for each user playlist, a list of this format: 
            # [playlist_name, [track_names], [track_artists], [track_durations], [track_durations]]
            playlist_data = get_playlist_information(data)
            print(f'Playlist data is {playlist_data}')

    return render_template('playlist.html')

@app.route('/account_settings_page')
def account_settings_page():
    return render_template('account_settings.html')

@app.route('/account_contact_page')
def account_contact_page():
    return render_template('account_contact.html')

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

def get_playlist_information(data):
    playlists = data['items']
    playlist_uris = [playlist['uri'] for playlist in playlists]
    playlist_names = [playlist['name'] for playlist in playlists]
    
    playlist_id = ''
    playlist = ''
    playlist_list = []

    for playlist_uri in playlist_uris:
        playlist_id = playlist_uri.split(':')[-1]
        playlist = spotify.playlist(playlist_id = playlist_id)
        playlist_list.append(playlist)

    playlist_info_list = []
    track_names = []
    track_albums = []
    track_artists = []
    track_durations = []

    for index, playlist in enumerate(playlist_list):
        for track in playlist['tracks']['items']:
            track_names.append(track['track']['name'])
            track_albums.append(track['track']['album']['name'])
            track_artists.append(track['track']['artists'][0]['name'])
            track_durations.append(datetime.timedelta(milliseconds = track['track']['duration_ms']))

        playlist_info_list.append(
            [playlist_names[index], track_names, track_albums, track_artists, track_durations]
        )

        track_names = []
        track_albums = []
        track_artists = []
        track_durations = []

    return playlist_info_list
