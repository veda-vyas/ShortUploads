from flask import Flask, flash, redirect, render_template, \
     request, jsonify, url_for, session, send_from_directory, \
     make_response, Response as ress, send_file
from datetime import datetime, timedelta, date
import time
import json
import os
import logging
from logging.handlers import RotatingFileHandler
import sys
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import Index
from flask.ext.login import LoginManager, login_required, login_user, \
    logout_user, current_user, UserMixin
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError
from config import BaseConfig
import StringIO
import csv
import re
import mimetypes
import pytz
from werkzeug.utils import secure_filename
import zipfile
from sqlalchemy import cast, Date, extract

# Global vars
IST = pytz.timezone('Asia/Kolkata')
root = os.path.join(os.path.dirname(os.path.abspath(__file__)))
os.environ['http_proxy'] = ''
os.environ['https_proxy'] = ''

class Auth:
    CLIENT_ID = ('891614416155-5t5babc77fivqfslma1c3u6r2r9fp1o1.apps.googleusercontent.com')
    CLIENT_SECRET = 'UnGr0t5VT0d3l4PLgICkQoy6'
    REDIRECT_URI = 'https://127.0.0.1:5000/oauth2callback'
    AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
    TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
    USER_INFO = 'https://www.googleapis.com/userinfo/v2/me'
    SCOPE = ['profile', 'email']

class Config:
    APP_NAME = "Short Uploads"
    SECRET_KEY = "somethingsecret"

app = Flask(__name__)

app.debug_log_format = "[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s"
log_path = os.path.join(os.getcwd(),'logs.log')
log_path = 'logs.log'
logHandler = RotatingFileHandler(log_path, maxBytes=10000, backupCount=1)
logHandler.setLevel(logging.NOTSET)
app.logger.addHandler(logHandler)
app.logger.setLevel(logging.NOTSET)
login_log = app.logger
app.debug = True
app.secret_key = "some_secret"
app.config.from_object(BaseConfig)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "googlelogin"
login_manager.session_protection = "strong"

#from werkzeug.serving import make_ssl_devcert
#make_ssl_devcert('./ssl', host='localhost')

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(200))
    tokens = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now(IST))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_google_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)
    if state:
        return OAuth2Session(
            Auth.CLIENT_ID,
            state=state,
            redirect_uri=Auth.REDIRECT_URI)
    oauth = OAuth2Session(
        Auth.CLIENT_ID,
        redirect_uri=Auth.REDIRECT_URI,
        scope=Auth.SCOPE)
    return oauth

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        app.logger.info(e)
        return render_template('error.html')

@app.route('/profile')
@login_required
def profile():
    try:
        email = session['email']
        user = User.query.filter_by(email=email).first()
        return render_template('profile.html', user=user)   
    except Exception as e:
        app.logger.info(e)
        return render_template('error.html')

@app.route('/library')
def library():
    try:
        trending = [["Trending 1","Trending 2","Trending 3","Trending 4","Trending 5", "Trending 6"],["Trending 7","Trending 8","Trending 9",None,None,None]]
        recent = [["Recent 1", "Recent 2", "Recent 3", "Recent 4", "Recent 5", "Recent 6"]]
        series = [["Series 1", "Series 2", "Series 3", "Series 4", "Series 5", "Series 6"]]
        episodes = [["Episode 1", "Episode 2", "Episode 3", "Episode 4", "Episode 5", "Episode 6"]]
        channels = [[["Channel 1", "Channel 2", "Channel 3", "Channel 4", "Channel 5", "Channel 6"],["Channel 7", "Channel 8", "Channel 9", "Channel 10", "Channel 11", "Channel 12"]]]
        return render_template('library.html', trending=trending, recent=recent, series=series, episodes=episodes, channels=channels)   
    except Exception as e:
        app.logger.info(e)
        return render_template('error.html')

@app.route('/playlist/<name>')
def playlist(name=None):
    try:
        playlist = []
        duration = None

        if name=="trending":
            playlist = [["Trending 1","Trending 2","Trending 3","Trending 4","Trending 5", "Trending 6"],["Trending 7","Trending 8","Trending 9",None,None,None]]
            duration = "9:55"
        if name=="recent":
            playlist = [["Recent 1", "Recent 2", "Recent 3", "Recent 4", "Recent 5", "Recent 6"]]
            duration = "9:55"
        if name=="episodes":
            playlist = [["Episode 1", "Episode 2", "Episode 3", "Episode 4", "Episode 5", "Episode 6"]]
            duration = "9:55"
        if name=="series":
            playlist = [["Series 1", "Series 2", "Series 3", "Series 4", "Series 5", "Series 6"]]
            duration = "9 Episodes"
        if name=="channels":
            playlist = [["Channel 1", "Channel 2", "Channel 3", "Channel 4", "Channel 5", "Channel 6",],["Channel 7", "Channel 8", "Channel 9", "Channel 10", "Channel 11", "Channel 12"]]
            duration = "12 Videos"

        return render_template('playlist.html', name=name, playlist=playlist, duration=duration)   
    except Exception as e:
        app.logger.info(e)
        return render_template('error.html')

@app.route('/series/<name>')
def series(name=None):
    try:
        playlist = []
        duration = None
        temppl = []
        for i in range(10):
            if i % 5 == 0 or i == 9:
                playlist.append(temppl)
                temppl = []
            temppl.append("Episode "+str(i+1))
        return render_template('playlist.html', name=name, playlist=playlist)   
    except Exception as e:
        app.logger.info(e)
        return render_template('error.html')

@app.route('/channels/<name>')
def channels(name=None):
    try:
        playlist = []
        duration = None
        temppl = []
        for i in range(13):
            if i % 5 == 0 or i == 12:
                playlist.append(temppl)
                temppl = []
            temppl.append("Video "+str(i+1))
        return render_template('playlist.html', name=name, playlist=playlist)   
    except Exception as e:
        app.logger.info(e)
        return render_template('error.html')

@app.route('/watch/<name>/<video>')
def watch(name=None, video=None):
    try:
        return render_template('watch.html', name=video+" - from YouTube")   
    except Exception as e:
        app.logger.info(e)
        return render_template('error.html')

@app.route('/upload')
@login_required
def upload():
    try:
        email = session['email']
        user = User.query.filter_by(email=email).first()
        return render_template('upload.html', user=user)   
    except Exception as e:
        app.logger.info(e)
        return render_template('error.html')

@app.route('/googlelogin', methods=['GET', 'POST'])
def googlelogin():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    google = get_google_auth()
    auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback', methods=['GET', 'POST'])
def callback():
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('index'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'You denied access.'
        return 'Error encountered.'
    if 'code' not in request.args and 'oauth_state' not in request.args:
        return redirect(url_for('googlelogin'))
    else:
        google = get_google_auth(state=session['oauth_state'])
        try:
            token = google.fetch_token(
                Auth.TOKEN_URI,
                client_secret=Auth.CLIENT_SECRET,
                authorization_response=request.url)
        except HTTPError:
            return 'HTTPError occurred.'
        google = get_google_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            email = user_data['email']
            user = User.query.filter_by(email=email).first()
            if user is None:
                user = User()
                user.email = email
            user.name = user_data['name']
            print(token)
            user.tokens = json.dumps(token)
            user.avatar = user_data['picture']
            db.session.add(user)

            db.session.commit()
            login_user(user)
            session['email'] = email    
            app.logger.info(session['email'])
            return redirect(url_for('profile'))
    return 'Could not fetch your information.'

@app.route('/error')
@login_required
def error():
    return render_template('error.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/styles/<path:path>')
def send_stylesheets(path):
    app.logger.info("seeking for %s from %s at %s"%(path, request.headers.get('X-Forwarded-For', request.remote_addr), datetime.now()))
    return send_from_directory(root+"/styles", path)

@app.route('/mdb/<path:path>')
def mdb(path):
    app.logger.info("seeking for %s from %s at %s"%(path, request.headers.get('X-Forwarded-For', request.remote_addr), datetime.now()))
    return send_from_directory(root+"/MDB Free", path)

@app.route('/images/<path:path>')
def send_images(path):
    app.logger.info("seeking for %s from %s at %s"%(path, request.headers.get('X-Forwarded-For', request.remote_addr), datetime.now()))
    return send_from_directory(root+"/images", path)

@app.route('/fonts/<path:path>')
def send_fonts(path):
    app.logger.info("seeking for %s from %s at %s"%(path, request.headers.get('X-Forwarded-For', request.remote_addr), datetime.now()))
    return send_from_directory(root+"/fonts", path)

@app.route('/scripts/<path:path>')
def send_javascripts(path):
    app.logger.info("seeking for %s from %s at %s"%(path, request.headers.get('X-Forwarded-For', request.remote_addr), datetime.now()))
    return send_from_directory(root+"/scripts", path)

@app.route('/content/<path:path>')
@login_required
def send_content(path):
    return send_from_directory(root+"/content", path)

if __name__ == "__main__":
    db.create_all()
    app.debug = True
    app.run(ssl_context=('ssl.crt','ssl.key'))
