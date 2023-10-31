from flask import Flask, render_template, request, redirect

app = Flask(__name__)

@app.get('/')
def index_page():
    return render_template('index.html')

@app.get

@app.get('/signup_page')
def signup_page():
    return render_template('signup.html')