from flask import Flask, render_template, request, redirect

app = Flask(__name__)

@app.get('/')

def index_page():
    return render_template('index.html')

@app.get

@app.get('/signup_page')
def signup_page():
    return render_template('signup.html')
def index():
    return render_template('index.html')

@app.get('/sign_in_page')
def sign_in_page():
    return render_template('sign_in_page.html')

@app.post('/sign_in_page')
def sign_in():
    # get data here when more functionality is established 
    return redirect('index.html')

@app.get('/discussion')
def discussion_page():
    return render_template('discussion.html')

