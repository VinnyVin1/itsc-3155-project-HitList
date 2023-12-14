import pytest
from flask import Flask
from flask.testing import FlaskClient
from datetime import datetime

@pytest.fixture
def app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_profile_page(client):
    response = client.get('/profile_page')
    assert response.status_code == 200
    assert b'Profile' in response.data
    assert b'User ID:' in response.data
    assert b'Upload Playlists' in response.data
    assert b'Posts' in response.data
    no_posts = client.get('/profile_page?user_posts=[]')
    assert b'You have no posts!' in no_posts.data

    posts = {
        'user_name': 'user1',
        'created': datetime.now(),
        'title': 'Test 1',
        'content': 'This is a test for profile page posts.'
    }
    create_post_response = client.post('/create_post', data=posts, follow_redirects=True)
    assert create_post_response.status_code == 200
    response_after_post = client.get('/profile_page')
    assert b'Test 1' in response_after_post.data
    assert b'This is a test for profile page posts.' in response_after_post.data