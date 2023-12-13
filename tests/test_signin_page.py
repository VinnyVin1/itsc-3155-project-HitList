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

def test_signin_page(client):
    response = client.get('/signin_page')
    assert response.status_code == 200
    assert b'Sign in' in response.data

    valid_input = {
        'email': 'jsmith123@gmail.com',
        'password': 'passwordABC123'
    }
    valid_input_result = client.post('/signin_page', data=valid_input, follow_redirects=True)
    assert valid_input_result.status_code == 200
    assert b'Welcome, jsmith123@gmail.com!' in valid_input_result.data

    bad_input_missing_password = {
        'email': 'jsmith123@gmail.com',
        'password': ''
    }
    bad_input_missing_password_result = client.post('/signin_page', data=bad_input_missing_password, follow_redirects=True)
    assert bad_input_missing_password_result.status_code == 400
    assert b'Invalid password' in bad_input_missing_password_result.data

    bad_input_missing_email = {
        'email': 'email123',
        'password': 'passwordABC123'
    }
    bad_input_missing_email_result = client.post('/signin_page', data=bad_input_missing_email, follow_redirects=True)
    assert bad_input_missing_email_result.status_code == 400
    assert b'Invalid email' in bad_input_missing_email_result.data