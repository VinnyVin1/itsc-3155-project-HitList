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

def test_signup_page(client):
    response = client.get('/sign_up_page')
    assert response.status_code == 200
    assert b'Sign up' in response.data

    valid_input = {
        'first_name': 'John',
        'last_name': 'Smith',
        'email': 'jsmith123@gmail.com',
        'username': 'jsmithy',
        'display_name': 'John_S',
        'password': 'passwordABC123',
        'confirm_password': 'passwordABC123',
        'auth': 'checked'
    }
    signup_response = client.post('/sign_up_page', data=valid_input, follow_redirects=True)
    assert signup_response.status_code == 200
    assert b'Welcome, John_S!' in signup_response.data

    bad_input_mismatched_passwords = {
        'first_name': 'Hank',
        'last_name': 'Hill',
        'email': 'hankhill@gmail.com',
        'username': 'hankhill',
        'display_name': 'Hank_H',
        'password': 'passwordABC123',
        'confirm_password': 'password',
        'auth': 'checked'
    }
    bad_input_mismatched_passwords_result = client.post('/sign_up_page', data=bad_input_mismatched_passwords, follow_redirects=True)
    assert bad_input_mismatched_passwords_result.status_code == 400
    assert b'Both passwords do not match' in bad_input_mismatched_passwords_result.data

    bad_input_missing_fields = {
        'first_name': '',
        'last_name': 'Smith',
        'email': 'jsmith123@gmail.com',
        'username': 'jsmithy',
        'display_name': 'John_S',
        'password': 'passwordABC123',
        'confirm_password': 'passwordABC123',
        'auth': 'checked'
    }
    bad_input_missing_fields_result = client.post('/sign_up_page', data=bad_input_missing_fields, follow_redirects=True)
    assert bad_input_missing_fields_result.status_code == 400
    assert b'This field is required' in bad_input_missing_fields_result.data