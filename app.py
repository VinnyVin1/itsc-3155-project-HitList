from flask import Flask, render_template, request, redirect

app = Flask(__name__)

contact_storage = []

@app.get('/')
def index_page():
    return render_template('index.html')

@app.get('/signup_page')
def signup_page():
    return render_template('signup.html')

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

def store_message_in_file(message):
    with open('contact_messages.txt', 'a') as file:
        file.write(message + '\n')

@app.route('/contact_us', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        message = request.form['message']

        contact_storage.append({
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'message': message
        })

        store_message_in_file(f"Name: {first_name} {last_name}, Email: {email}, Message: {message}")

        return render_template('contact_success.html', first_name=first_name)

    return render_template('contact.html')