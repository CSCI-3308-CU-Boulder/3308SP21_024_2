"""
Prerequisites
    pip3 install spotipy Flask Flask-Session
    export SPOTIPY_CLIENT_ID=client_id_here
    export SPOTIPY_CLIENT_SECRET=client_secret_here
    export SPOTIPY_REDIRECT_URI='http://127.0.0.1:5000
"""

import os
from flask import Flask, session, request, redirect
from flask_session import Session
import spotipy
from spotipy.oauth2 import SpotifyOAuth
import uuid
import json
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(64)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './.flask_session/'
Session(app)

caches_folder = './.spotify_caches/'
if not os.path.exists(caches_folder):
    os.makedirs(caches_folder)

def session_cache_path():
    return caches_folder + session.get('uuid')

def get_spotify():
	cache_handler = spotipy.cache_handler.CacheFileHandler(cache_path=session_cache_path())
	auth_manager = spotipy.oauth2.SpotifyOAuth(scope='playlist-read-private playlist-modify-private playlist-modify-private',
		cache_handler=cache_handler, 
		show_dialog=True)
	if not auth_manager.validate_token(cache_handler.get_cached_token()):
		return redirect('/')
	spotify = spotipy.Spotify(auth_manager=auth_manager)
	return spotify

def spotify_auth():
    if not session.get('uuid'):
        #Visitor is unknown, give random ID
        session['uuid'] = str(uuid.uuid4())

    cache_handler = spotipy.cache_handler.CacheFileHandler(cache_path=session_cache_path())
    auth_manager = spotipy.oauth2.SpotifyOAuth(scope='playlist-read-private playlist-modify-private playlist-modify-private',
                                                cache_handler=cache_handler, 
                                                show_dialog=True)

    if request.args.get("code"):
        #Being redirected from Spotify auth page
        auth_manager.get_access_token(request.args.get("code"))
        return redirect('/profile')

    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        #Display sign in link when no token
        auth_url = auth_manager.get_authorize_url()
        return f'<h2><a href="{auth_url}">Sign in</a></h2>'

    #Signed in, display data
    spotify = spotipy.Spotify(auth_manager=auth_manager)
    return spotify

def sign_out():
    try:
        # Remove the CACHE file (.cache-test) so that a new user can authorize.
        os.remove(session_cache_path())
        session.clear()
    except OSError as e:
        print ("Error: %s - %s." % (e.filename, e.strerror))
    return redirect('/')

def playlists():
	spotify = get_spotify()
	results = []
	for i in spotify.current_user_playlists()['items']:
		results.append({'name': i['name'], 'id': i['uri'].split(':')[-1]})
	return json.dumps(results)

def songs(pl_id):
	spotify = get_spotify()
	results = []
	for i in spotify.playlist_items(pl_id, additional_types=['track'])['items']:
		artists = [x['name'] for x in i['track']['artists']][0]
		results.append({'track': i['track']['name'], 'artist': artists})
	return json.dumps(results)

def current_user():
	spotify = get_spotify()
	return json.dumps(spotify.current_user())

def addPlaylist(u_id, name):
	spotify = get_spotify()
	spotify.user_playlist_create(u_id, name, public=False, collaborative=False, description="A playlist created by PlaySync on "+str(datetime.today().strftime('%Y-%m-%d')))

def addSong(pl_id, artist, track):
	spotify = get_spotify()
	result = spotify.search(q=f'{artist} {track}', limit=1, type='track')
	#print(result['tracks']['items'][0]['id'])
	if result['tracks']['total'] == 0:
		return 'Failed to find track'	
	spotify.playlist_add_items(pl_id, [result['tracks']['items'][0]['uri']])
	return json.dumps(result)
