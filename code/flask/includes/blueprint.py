from flask import Blueprint, render_template, abort, request, make_response, redirect
from jinja2 import TemplateNotFound
import json
from urllib.parse import quote, unquote
from includes.userauth import *
from includes.api_auth import *
from includes.tasker import *
from includes.userprofile import *
import api.spotify as spotify
import api.youtubeOAuth as yt
import hashlib

landing_page = Blueprint('landing_page', __name__, template_folder='templates')
verify_page = Blueprint('verify_page', __name__, template_folder='templates')
login_page = Blueprint('login_page', __name__, template_folder='templates')
logout_page = Blueprint('logout_page', __name__, template_folder='templates')
userauth_page = Blueprint('userauth_page', __name__, template_folder='templates')
signup_page = Blueprint('signup_page', __name__, template_folder='templates')
useradd_page = Blueprint('useradd_page', __name__, template_folder='templates')
about_page = Blueprint('about_page', __name__, template_folder='templates')
youtube_operation = Blueprint('youtube_operation', __name__, template_folder='templates')
authadd_page = Blueprint('authadd_page', __name__, template_folder='templates')
authget_page = Blueprint('authget_page', __name__, template_folder='templates')
transfer_page = Blueprint('transfer_page', __name__, template_folder='templates')
profile_page = Blueprint('profile_page', __name__, template_folder='templates')
youtube_auth = Blueprint('youtube_auth', __name__, template_folder='templates')
update_email = Blueprint('update_email', __name__, template_folder='templates')
spotify_api = Blueprint('spotify_api', __name__, template_folder='templates')
spotify_auth = Blueprint('spotify_auth', __name__, template_folder='templates')
spotify_callback = Blueprint('spotify_callback', __name__, template_folder='templates')
spotify_remove = Blueprint('spotify_remove', __name__, template_folder='templates')
profile_page_password = Blueprint('profile_page_password', __name__, template_folder='templates')
profile_page_delete_acc = Blueprint('profile_page_delete_acc', __name__, template_folder='templates')
youtube_oauth = Blueprint('youtube_oauth', __name__, template_folder='templates')
youtube_callback = Blueprint('youtube_callback', __name__, template_folder='templates')
yto = Blueprint('yto', __name__, template_folder='templates')

@landing_page.route('/')
@landing_page.route('/landing')
def landing():
    # if 'visited' in request.cookies: # Not new comer
    if 'user' in request.cookies: # Logged in
        user = valid_user(request.cookies.get('user'))
            
        if user != None:
            return render_template('authed.html', title='Authenticated User - PlaySync', username=user)
        else: # Invalid Login Info
            resp = make_response(render_template('login.html', title='Please log in - PlaySync'))
            resp.set_cookie('user', expires=0)
            return resp
    else: # Not Logged In
        return render_template('landing.html', title='Consider Log-In or Register - PlaySync', visitor_status="Returning Visitor")
    # else:
        # resp = make_response(render_template('landing.html', title='Welcome, first-time visitor - PlaySync', visitor_status="New Visitor"))
        # resp.set_cookie('visited', '1')
        # return resp

@landing_page.route('/google083b603006fd3547.html')
def googleVerify():
    return render_template('google083b603006fd3547.html')

@login_page.route('/login')
def login():
    if 'user' in request.cookies: # Logged in
        user = valid_user(request.cookies.get('user'))
        if user != None:
            return redirect("./", code=302) # Protect from CSRF attacks
    return render_template('login.html', title='Log-in form - PlaySync')

@logout_page.route('/logout')
def logout():
    resp = make_response(redirect("./", code=302))
    resp.set_cookie('user', expires=0)
    return resp

@userauth_page.route('/userauth', methods=['POST'])
def userauth():
    if 'user' in request.cookies: # Already logged in
        user = valid_user(request.cookies.get('user'))
        if user != None: # If is valid user
            return redirect("./", code=302) # Protect from CSRF attacks
    
    resp = make_response(redirect("./", code=302))

    login_name = request.form.get('uname')
    login_passwd = hashlib.sha256(request.form.get('psw').encode('utf-8')).hexdigest()
    compressed_cookie = login_passwd+':'+login_name

    # Check if this cookie is valid
    if(valid_user(compressed_cookie)!=None):    
        resp.set_cookie('user', compressed_cookie) # Set cookie if valid
    return resp

@signup_page.route('/signup')
def signup():
    if 'user' in request.cookies: # Logged in
        user = valid_user(request.cookies.get('user'))
        if user != None:
            return redirect("./", code=302) # Protect from CSRF attacks
    return render_template('signup.html')

@useradd_page.route('/useradd', methods=['POST'])
def useradd():
    if 'user' in request.cookies: # Logged in
        user = valid_user(request.cookies.get('user'))
        if user != None:
            return redirect("./", code=302) # Protect from CSRF attacks

    add_name = request.form.get('uname')
    add_psw = hashlib.sha256(request.form.get('psw').encode('utf-8')).hexdigest()
    if check_user_exist(add_name) != None:
        return redirect("./signup", code=302) # Failed to register
    
    if 'email' in request.form and request.form.get('email') != '':
        # Email opt-in
        add_user(add_name, add_psw, request.form.get('email'))
    else:
        # Email opt-out
        add_user(add_name, add_psw)
    resp = make_response(redirect("./", code=302))
    compressed_cookie = add_psw+':'+add_name
    
    # Check if this cookie is valid
    if(valid_user(compressed_cookie)!=None):    
        resp.set_cookie('user', compressed_cookie) # Set cookie if valid
    return resp

@about_page.route('/about')
def about():
    return render_template('about.html')

# POST: auth_type=sometype&auth_body=somebody
# Should be urlencoded
@authadd_page.route('/authadd', methods=['POST'])
def authadd():
    if 'user' in request.cookies: # Logged in
        user = valid_user(request.cookies.get('user'))
            
        if user != None:
            if "auth_type" in request.form and "auth_body" in request.form:
                uid = psql_get_uid(user)                
                psql_write_auth(uid, unquote(request.form.get('auth_type')), unquote(request.form.get('auth_body')))
                return "addok"
        else: # Invalid Login Info
            return "badlogin"
    else: # Not Logged In
        return redirect("./", code=302) # Protect from CSRF attacks

# POST: auth_type=sometype
# Should be urlencoded if needed
@authget_page.route('/authget', methods=['POST'])
def authget():
    if 'user' in request.cookies: # Logged in
        user = valid_user(request.cookies.get('user'))
            
        if user != None:
            if "auth_type" in request.form:
                uid = psql_get_uid(user)                
                auth_body = psql_check_auth(uid, unquote(request.form.get('auth_type')))
                json_response = {}

                json_response['type'] = request.form.get('auth_type')
                json_response['body'] = auth_body

                return json.dumps(json_response)
        else: # Invalid Login Info
            return "badlogin"
    else: # Not Logged In
        return redirect("./", code=302) # Protect from CSRF attacks

# POST: user=$cookies['user']&op=$operation&param=$parameters
@youtube_operation.route('/youtube', methods=['POST'])
def youtube_ops():
    json_response = {}
    user = unquote(request.form.get('user'))
    if user != "" and valid_user(user) != None:
        # Valid operation
        uid = get_uid(valid_user(user))
        # Get header saved in db
        auth_body = psql_check_auth(uid, "ytmusic")
        if auth_body == "":
            json_response['status'] = "fail"
            json_response['message'] = "invalid auth"
            return json.dumps(json_response)
        else:
            credential = credential_youtube(auth_body)
            ytapi=youtube_music_tasker(credential[1])
            # Handle the op
            op = unquote(request.form.get('op'))
            # playlist - unparameterized
            # songlist - POST parameterized as playlistid=c0dedeadbeef
            # newlist - POST parameterized as name=cafebabe&desc=beefcode&access=PRIVATE&tracks=id$id$id$id
            # searchsong - POST parameterized as title=beefbabe&artist=deadbee&misc=abadcafe}
            if op == "playlist": # Show playlist
                return ytapi.show_playlist()
            elif op == "songlist":
                return ytapi.show_song_in_playlist(request.form.get('playlistid'))
            elif op == "newlist":
                new_name = unquote(request.form.get('name'))
                new_desc = ""
                if "desc" in request.form:
                    new_desc = unquote(request.form.get('desc'))
                # new_access = request.form.get('access')
                new_tracks=[]
                if "tracks" in request.form:
                    new_tracks = unquote(request.form.get('tracks')).split('$')
                ret_tuple = ytapi.new_playlist(playlist_name=new_name, desc=new_desc, tracks=new_tracks)
                if ret_tuple[0] == -1:
                    json_response['status'] = "fail"
                    json_response['message'] = ret_tuple[2]
                    return json.dumps(json_response)
                elif ret_tuple[0] == -2:
                    json_response['status'] = "crash"
                    json_response['message'] = ret_tuple[2]
                    return json.dumps(json_response)
                else:
                    json_response['status'] = "success"
                    json_response['newlistid'] = ret_tuple[1]
                    json_response['message'] = ret_tuple[2]
                    return json.dumps(json_response)
            elif op == "searchsong":
                title = unquote(request.form.get('title'))
                artist = ""
                if "artist" in request.form:
                    artist = unquote(request.form.get('artist'))
                misc = ""
                if "misc" in request.form:
                    misc = unquote(request.form.get('misc'))
                return ytapi.search_song(song_title=title, song_artist=artist, song_misc=misc)
            elif op == "addsong":
                new_tracks=[]
                if "tracks" in request.form and "playlistid" in request.form:
                    new_tracks = unquote(request.form.get('tracks')).split('$')
                    ret_tuple = ytapi.add_songs(request.form.get('playlistid'), new_tracks)
                    if ret_tuple[0] == -2:
                        json_response['status'] = "crash"
                        json_response['message'] = "crashed in creation"
                        return json.dumps(json_response)
                    else:
                        json_response['status'] = "success"
                        json_response['message'] = ret_tuple[2]
                        return json.dumps(json_response)
                else:
                    json_response['status'] = "fail"
                    json_response['message'] = "parameters missing"
                    return json.dumps(json_response)
            else:
                json_response['status'] = "fail"
                json_response['message'] = "unknown op"
                return json.dumps(json_response)
    else:
        abort(403)

# POST: user=$cookies['user']&op=$operation&param=$parameters
@transfer_page.route('/transfer')
def transfer_list():
    # if 'visited' in request.cookies: # Not new comer
    if 'user' in request.cookies: # Logged in
        user = valid_user(request.cookies.get('user'))
            
        if user != None:
            return render_template('playlist_page.html', title='Authenticated User - PlaySync', username=user)
        else: # Invalid Login Info
            resp = make_response(render_template('login.html', title='Please log in - PlaySync'))
            resp.set_cookie('user', expires=0)
            return resp
    else: # Not Logged In
        return render_template('landing.html', title='Consider Log-In or Register - PlaySync', visitor_status="Returning Visitor")
    # else:
        # resp = make_response(render_template('landing.html', title='Welcome, first-time visitor - PlaySync', visitor_status="New Visitor"))
        # resp.set_cookie('visited', '1')
        # return resp

@profile_page.route('/profile')
def profile():
    email = ""
    auth_body= ""
    if 'user' in request.cookies: # Logged in
        user = valid_user(request.cookies.get('user'))
        email = get_email(user)
        auth_body = get_auth(user)
        spotifyName = spotify.get_name()
        return render_template('profile.html', email=email, auth_body=auth_body, spotifyName=spotifyName)
    else: # Not Logged In
        return redirect("./", code=302)
    
@profile_page_password.route('/updatepw', methods=["POST"])
def updatePw():
    user = valid_user(request.cookies.get('user'))
    uid = psql_get_uid(user)
    new_pw = hashlib.sha256(request.form.get('psw').encode('utf-8')).hexdigest()
    compressed_cookie = new_pw+':'+user
    psql_update_pw(uid, new_pw)
    return redirect('/profile')

@profile_page_delete_acc.route('/delete', methods=["POST"])
def removeAcc():
    user = valid_user(request.cookies.get('user'))
    uid = psql_get_uid(user)
    pw = hashlib.sha256(request.form.get('psw').encode('utf-8')).hexdigest()
    if psql_read_user_psw(user, pw):
        psql_remove_acc(uid)
        return redirect('/')
    return redirect('/profile')

@youtube_auth.route('/youtubeauth', methods=['POST'])
def youtubeAuth():
    auth_body = request.form['auth_body']
    user = valid_user(request.cookies.get('user'))
    add_auth(user, auth_body)
    return redirect('./profile')

@update_email.route('/updatemail', methods=['POST'])
def updateEmail():
        email = request.form['email']
        mailing_bool = "FALSE"
        if request.form.get('mailing-list'):
            mailing_bool = "TRUE"
        user = valid_user(request.cookies.get('user'))
        update_usr_email(user, email, mailing_bool)
        return redirect('./profile')    

@spotify_api.route('/spotify', methods=['POST'])
def spotifyapi():
    json_response = {}
    user = unquote(request.form.get('user'))
    uname = valid_user(user)
    if user != "" and uname != None:
        # Valid operation
        uid = get_uid(uname)
        # Get header saved in db
        auth_body = psql_check_auth(uid, "spotify")
        if auth_body != "Authorized":
            json_response['status'] = "fail"
            json_response['message'] = "Not Authorized"
            return json.dumps(json_response)
        else:
            # Handling POST requests
            # Available variables:
            #   - uname: username of the user
            #   - uid: uid of the user

            #Spotify authorization is currently not initiated and removed on use, therefore, if we are authorized then no steps need to be taken to grant access.
            
            # Handle the operation
            op = unquote(request.form.get('op'))
            # playlist - unparameterized, return a JSON string of playlists owned by user
            # songlist - POST parameterized as playlistid=c0dedeadbeef
            # newlist - POST parameterized as name=cafebabe&desc=beefcode&access=PRIVATE&tracks=id$id$id$id
            # searchsong - POST parameterized as title=beefbabe&artist=deadbee&misc=abadcafe}
            if op == "playlist": # Show playlist
                return spotify.playlists(uname)
            elif op == "songlist":
                return spotify.songs(uname, unquote(request.form.get('playlistid')))
            elif op == "newlist":
                new_name = unquote(request.form.get('name'))
                new_desc = ""
                if "desc" in request.form:
                    new_desc = unquote(request.form.get('desc'))
                # new_access = request.form.get('access')
                new_tracks=[]
                if "tracks" in request.form:
                    new_tracks = unquote(request.form.get('tracks')).split('$')

                # TO-DO: this func return a Dict containing at least playlistID
                add_list_result = spotify.add_playlist(uname, new_name)
                add_list_result['status'] = "success"
                playlist_id = add_list_result['playlistid']
                ##################### TO-DO: CHOOSE ONE ######################
                # status = spotify.add_song(uname, playlist_id, new_tracks) # if add_song accepts one ID (string) at a time
                # # check for status, abort if any error
                # if status != 'done':
                #     add_list_result['status'] = "fail"
                #     add_list_result['message'] = "error in adding song"
                #     break
                ########################### OR ###############################
                if len(new_tracks)>0:
                    status = spotify.add_song(uname, playlist_id, new_tracks) # if accepts list of ID (string)
                    if status != 'done':
                        add_list_result['status'] = "fail"
                        add_list_result['message'] = "error in adding song"
                ###############################################################
                return json.dumps(add_list_result)
            elif op == "searchsong":
                title = unquote(request.form.get('title'))
                artist = ""
                if "artist" in request.form:
                    artist = unquote(request.form.get('artist'))
                return spotify.search_song(uname, artist, title)
            elif op == "addsong":
                new_tracks=[]
                if "tracks" in request.form and "playlistid" in request.form:
                    playlist_id = unquote(request.form.get('playlistid'))
                    new_tracks = unquote(request.form.get('tracks')).split('$')
                    json_response['status'] = "success"
                    json_response['playlistid'] = playlist_id
                    ##################### TO-DO: CHOOSE ONE ######################
                    #     status = spotify.add_song(uname, playlist_id, new_tracks) # if add_song accepts one ID (string) at a time
                    #     # check for status, abort if any error
                    #     if status != 'done':
                    #         json_response['status'] = "fail"
                    #         json_response['message'] = "error in adding song"
                    #         break
                    ########################### OR ###############################
                    if len(new_tracks)>0:
                        status = spotify.add_song(uname, playlist_id, new_tracks) # if accepts list of ID (string)
                        if status != 'done':
                            json_response['status'] = "fail"
                            json_response['message'] = "error in adding song"
                    ###############################################################
                    return json.dumps(json_response)
            else:
                json_response['status'] = "fail"
                json_response['message'] = "unknown op"
                return json.dumps(json_response)
    else:
        abort(403)

@spotify_auth.route('/spotifyauth')
def spotifyAuth():
    user = request.cookies.get('user').split(':')[1]
    return spotify.auth_spotify(user)

@spotify_callback.route('/spotifycallback')
def spotifycallback():
    user = request.cookies.get('user').split(':')[1]
    add_spotify_auth(user)
    return spotify.callback(user)

@spotify_remove.route('/spotifyremove')
def spotifyRemove():
    user = request.cookies.get('user').split(':')[1]
    remove_spotify_auth(user)
    return spotify.sign_out(user)
    
@youtube_oauth.route('/ytoauth')
def ytoauth():
    return yt.authorize_yt()
    # flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    #   CLIENT_SECRETS_FILE, scopes=SCOPES)
    # flow.redirect_uri = 'https://playsync.me/ytcallback'
    # authorization_url, state = flow.authorization_url(
    #   # This parameter enables offline access which gives your application
    #   # both an access and refresh token.
    #   access_type='offline',
    #   # This parameter enables incremental auth.
    #   include_granted_scopes='false'
    # )
    # # Store the state in the session so that the callback can verify that
    # # the authorization server response.
    # flask.session['state'] = state
    # return flask.redirect(authorization_url)


@youtube_oauth.route('/ytcallback')
def ytcallback():
    return yt.oauth2callback()
    # state = flask.session['state']
    # flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    #   CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    # flow.redirect_uri = 'https://playsync.me/ytcallback'
    # authorization_response = flask.request.url
    # authorization_response = authorization_response.replace('http://127.0.0.1:81', 'https://playsync.me')
    # flow.fetch_token(authorization_response=authorization_response)
    # # Store the credentials in the session.
    # # ACTION ITEM for developers:
    # #     Store user's access and refresh tokens in your data store if
    # #     incorporating this code into your real app.
    # credentials = flow.credentials
    # flask.session['credentials'] = credentials_to_dict(credentials)
    # return flask.redirect('/profile')

@yto.route('/ytotest')
def ytotest():
    return yt.ytotest()
    # if 'credentials' not in flask.session:
    #   return flask.redirect('ytoauth')

    # # Load the credentials from the session.
    # credentials = google.oauth2.credentials.Credentials(
    #   **flask.session['credentials'])

    # client = googleapiclient.discovery.build(
    #   API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # return channels_list_by_username(client,
    #   part='snippet,contentDetails,statistics',
    #   forUsername='GoogleDevelopers')

# def channels_list_by_username(client, **kwargs):
#     response = client.channels().list(
#         **kwargs
#     ).execute()

#   return flask.jsonify(**response)

# def credentials_to_dict(credentials):
#     return {'token': credentials.token,
#           'refresh_token': credentials.refresh_token,
#           'token_uri': credentials.token_uri,
#           'client_id': credentials.client_id,
#           'client_secret': credentials.client_secret,
#           'scopes': credentials.scopes}