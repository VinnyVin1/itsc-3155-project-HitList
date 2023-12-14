import pytest
from flask import Flask, render_template
from flask.testing import FlaskClient

@pytest.fixture
def app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_contact_page(client):
    response = client.get('/contact_page')
    assert response.status_code == 200
    assert b'Contact' in response.data

    form_data = {
        'first_name': 'Hank',
        'last_name': 'Hill',
        'email': 'hankhill@gmail.com',
        'message': 'This is a test. Hello!'
    }
    response = client.post('/contact_us', data=form_data, follow_redirects=True)
    assert response.status_code == 200
    assert b'Thank you for contacting us!' in response.data

    bad_input_missing_fields = {
        'first_name': '',
        'last_name': '',
        'email': '',
        'message': ''
    }
    response = client.post('/contact_us', data=bad_input_missing_fields, follow_redirects=True)
    assert response.status_code == 400
    assert b'This field is required' in response.data

    bad_input_invalid_email = {
        'first_name': 'Hank',
        'last_name': 'Hill',
        'email': 'hankhill',
        'message': 'This is test for an invalid email input'
    }
    response = client.post('/contact_us', data=bad_input_invalid_email, follow_redirects=True)
    assert response.status_code == 400
    assert b'Please enter a valid email address' in response.data