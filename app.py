from flask import Flask, render_template, request, redirect

app = Flask(__name__)

@app.get('/')
def index():
    return render_template('index.html')

@app.route('/contact_us')
def contact():
    return render_template('contact.html')