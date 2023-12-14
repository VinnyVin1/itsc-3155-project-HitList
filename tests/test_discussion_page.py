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

def test_discussion_page(client):
    response = client.get('/discussion_page')
    assert response.status_code == 200
    assert b'Discussion' in response.data
    assert b'<form action="/discussion_page" method="post">' in response.data
    assert b'<label for="title">Title</label>' in response.data
    assert b'<textarea class="form-control" id="content" name="content" rows="3"></textarea>' in response.data
    assert b'<button type="submit">Submit</button>' in response.data

    bad_input_missing_fields = {
        'title': '',
        'content': ''
    }
    response = client.post('/discussion_page', data=bad_input_missing_fields, follow_redirects=True)
    assert response.status_code == 400
    assert b'This field is required' in response.data
