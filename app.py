import secrets

from authlib.oauth2 import OAuth2Error
from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

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
    client_kwargs={'scope': 'user:email'}
)
@app.route('/')
def home():
    user = session.get('user')
    if user:
        user_name = user.get('name', 'User')
        return f'Welcome {user_name}! <a href="/logout">Logout</a>'
    return (
        'Welcome to the Flask App.<br>'
        '<a href="/login/google">Login with Google</a><br>'
        '<a href="/login/github">Login with GitHub</a>'
    )

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
        nonce = session.pop('nonce', None)  # Retrieve and remove nonce from session
        user = google.parse_id_token(token, nonce=nonce)
        session['user'] = user
        return redirect(url_for('home'))
    except OAuth2Error as error:
        return f"Error: {error.error} - {error.description}"

@app.route('/callback/github')
def callback_github():
    try:
        token = github.authorize_access_token()
        resp = github.get('user')
        user = resp.json()
        user['name'] = user.get('name', user.get('login'))  # Use 'login' if 'name' is not available
        session['user'] = user
        return redirect(url_for('home'))
    except OAuth2Error as error:
        return f"Error: {error.error} - {error.description}"

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run()