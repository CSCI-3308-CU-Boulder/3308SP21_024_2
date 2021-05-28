import os
import flask
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

CLIENT_SECRETS_FILE = "api/client_secret.json"
SCOPES = ["https://www.googleapis.com/auth/youtube"]
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

caches_folder = '/tmp/youtube_caches/'
if not os.path.exists(caches_folder):
    os.makedirs(caches_folder)
    
def session_cache_path(user):
    return caches_folder + user

CLIENT_SECRETS_FILE = "api/client_secret.json"
SCOPES = ['https://www.googleapis.com/auth/youtube.force-ssl']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

def authorize_yt():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = 'https://playsync.me/ytcallback'
    authorization_url, state = flow.authorization_url(
      # This parameter enables offline access which gives your application
      # both an access and refresh token.
      access_type='offline',
      # This parameter enables incremental auth.
      include_granted_scopes='false'
    )
    # Store the state in the session so that the callback can verify that
    # the authorization server response.
    flask.session['state'] = state
    return flask.redirect(authorization_url)

def oauth2callback():
    state = flask.session['state']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = 'https://playsync.me/ytcallback'
    authorization_response = flask.request.url
    authorization_response = authorization_response.replace('http://127.0.0.1:81', 'https://playsync.me')
    flow.fetch_token(authorization_response=authorization_response)
    # Store the credentials in the session.
    # ACTION ITEM for developers:
    #     Store user's access and refresh tokens in your data store if
    #     incorporating this code into your real app.
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)
    return flask.redirect('/profile')

def ytotest():
    if 'credentials' not in flask.session:
        return flask.redirect('ytoauth')
    # Load the credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])
    client = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)
    return channels_list_by_username(client,
      part='snippet,contentDetails,statistics',
      forUsername='GoogleDevelopers')

def channels_list_by_username(client, **kwargs):
    response = client.channels().list(
        **kwargs
    ).execute()

    return flask.jsonify(**response)

def credentials_to_dict(credentials):
    return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}