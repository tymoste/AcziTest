import secrets
from datetime import datetime

from authlib.oauth2 import OAuth2Error
from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
import os
import sqlite3
import sqlite3
from datetime import datetime

def generate_html_from_database(db_file):
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute("SELECT id, name, joined, lastvisit, counter FROM users")
        rows = cursor.fetchall()

        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Users Data</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Users Data</h1>
                <table class="table table-striped mt-3">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Joined</th>
                            <th>Last Visit</th>
                            <th>Counter</th>
                        </tr>
                    </thead>
                    <tbody>
        """

        for row in rows:
            html += f"""
            <tr>
                <td>{row[0]}</td>
                <td>{row[1]}</td>
                <td>{row[2]}</td>
                <td>{row[3]}</td>
                <td>{row[4]}</td>
            </tr>
            """

        html += """
                    </tbody>
                </table>
            </div>

            <!-- Modal -->
            <div class="modal fade" id="dbModal" tabindex="-1" role="dialog" aria-labelledby="dbModalLabel" aria-hidden="true">
                <div class="modal-dialog" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="dbModalLabel">Database Connection</h5>
                            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                            </button>
                        </div>
                        <div class="modal-body">
                            <p>{modal_message}</p>
                        </div>
                    </div>
                </div>
            </div>

            <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.11.0/umd/popper.min.js"></script>
            <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"></script>
            <script>
                $(document).ready(function() {{
                    // Show the modal when the document is ready
                    $('#dbModal').modal('show');
                }});
            </script>
        </body>
        </html>
        """

        modal_message = "Successfully connected to the database."
    except sqlite3.Error as e:
        print(f"Error occurred: {e}")
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Error</title>
        </head>
        <body>
            <div class="container">
                <div class="alert alert-danger mt-5" role="alert">
                    Failed to connect to the database.
                </div>
            </div>
            <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.11.0/umd/popper.min.js"></script>
            <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"></script>
        </body>
        </html>
        """

        modal_message = "Failed to connect to the database."

    finally:
        if conn:
            conn.close()
    html = html.replace("{modal_message}", modal_message)

    return html


def add_or_update_user(db_file, name):
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        current_time = datetime.now().isoformat()
        cursor.execute("SELECT id, counter FROM users WHERE name = ?", (name,))
        row = cursor.fetchone()

        if row:
            user_id, counter = row
            cursor.execute("""
                UPDATE users
                SET lastvisit = ?, counter = ?
                WHERE id = ?
            """, (current_time, counter + 1, user_id))
            print(f"Updated user '{name}' with id {user_id}.")
        else:
            # User does not exist, insert new user
            cursor.execute("""
                INSERT INTO users (name, joined, lastvisit, counter)
                VALUES (?, ?, ?, ?)
            """, (name, current_time, current_time, 1))
            print(f"Added new user '{name}'.")

        conn.commit()
    except sqlite3.Error as e:
        print(f"Error occurred: {e}")
    finally:
        if conn:
            conn.close()

def initialize_database(db_file):
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        query = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            joined TEXT NOT NULL,
            lastvisit TEXT NOT NULL,
            counter INTEGER NOT NULL
        );
        """
        cursor.execute(query)
    except sqlite3.Error as e:
        print(e)
    finally:
        if conn:
            conn.close()


initialize_database("test.db")



app = Flask(__name__)
app.secret_key = os.urandom(24)
logged = None
# OAuth configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='664959834099-b1k9b7ctp95t95sp0ru64jaopuo35jni.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params={'scope': 'openid email profile'},
    redirect_uri='http://localhost:5000/callback',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={'scope': 'openid email profile'}
)
github = oauth.register(
    name='pki-appname',
    client_id='Ov23liHVHG6C6AMBcP1F',
    client_secret='c8b35fa27665e300cd608bcfc0b1ce545fca18d6',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    client_kwargs={'scope': 'user:email'},
    redirect_uri='https://aczitest.azurewebsites.net/callback/github'
)
@app.route('/')
def home():
    user = session.get('user')
    if user:
        navbar_content = f'''
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
            <a class="navbar-brand" href="#">Your App</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item active">
                        <a class="nav-link" href="#">Welcome {logged}! <span class="sr-only">(current)</span></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">Logout</a>
                    </li>
                </ul>
            </div>
        </nav>
        '''+ generate_html_from_database("test.db")
    else:
        navbar_content = f'''
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
            <a class="navbar-brand" href="#">Your App</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="#">Welcome to the Flask App.</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/login/google">Login with Google</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/login/github">Login with GitHub</a>
                    </li>
                </ul>
            </div>
        </nav>
        '''

    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Flask App</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        {navbar_content}
    </body>
    </html>
    '''

@app.route('/login/google')
def login_google():
    # Generate a nonce and store it in the session
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce
    redirect_uri = url_for('callback_google', _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/login/github')
def login_github():
    redirect_uri = url_for('callback_github', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/callback/google')
def callback_google():
    try:
        token = google.authorize_access_token()
        nonce = session.pop('nonce', None)
        user = google.parse_id_token(token, nonce=nonce)
        session['user'] = user
        global logged
        logged="google"
        email = user.get('email')
        name = user.get('name')
        if email:
            print(f"Google User Email: {email}")
            add_or_update_user("test.db",email)
        if name:
            print(f"Google User Name: {name}")
        return redirect(url_for('home'))
    except OAuth2Error as error:
        return f"Error: {error.error} - {error.description}"
@app.route('/callback/github')
def callback_github():
    try:
        token = github.authorize_access_token()
        resp = github.get('https://api.github.com/user', token=token)
        user_info = resp.json()
        email = user_info.get('email')
        username = user_info.get('login')
        if email:
            print(f"GitHub User Email: {email}")
        if username:
            print(f"GitHub Username: {username}")
            add_or_update_user("test.db",username)

        session['user'] = user_info
        global logged
        logged = "github"
        return redirect(url_for('home'))
    except OAuth2Error as error:
        return f"Error: {error.error} - {error.description}"



@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run()

#https://aczitest.azurewebsites.net/callback/github
#https://aczitest.azurewebsites.net/