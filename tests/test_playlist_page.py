import pytest
from flask import Flask
from flask.testing import FlaskClient

@pytest.fixture
def app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_playlist_page(client):
    response = client.get('/playlist_page')
    assert response.status_code == 200
    assert b'Playlist' in response.data
    assert b'Number of songs:' in response.data
    assert b'Owner:' in response.data
    assert b'Number of Artists:' in response.data
    assert b'<form action="/playlist/<playlist_id>" method="POST" class="playlist-form">' in response.data
    assert b'Your Playlists:' in response.data

    bad_input_missing_fields = {
        'playlist': ''
    }
    response = client.post('/playlist_page', data=bad_input_missing_fields, follow_redirects=True)
    assert response.status_code == 400
    assert b'This field is required' in response.data