from flask import Flask, render_template, request, redirect

app = Flask(__name__)

# Functions to get pages

@app.get('/')
def index_page():
    return render_template('index.html')

@app.get('/signin_page')
def signin_page():
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

@app.route('/account_settings_page')
def account_settings_page():
    return render_template('account_settings.html')

@app.route('/account_contact_page')
def account_contact_page():
    return render_template('account_contact.html')


# Functions for functionality

@app.post('/signin')
def sign_in():
    # get data here when more functionality is established 
    return redirect('index.html')

@app.post('/profile_info')
def profile_info():
    # get data here when more functionality is established 
    return redirect('account_settings.html')

@app.post('/send_contact')
def send_contact():
    # get data here when more functionality is established 
    return redirect('account_contact.html')