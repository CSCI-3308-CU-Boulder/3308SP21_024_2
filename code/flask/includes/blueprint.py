from flask import Blueprint, render_template, abort, request, make_response, redirect
from jinja2 import TemplateNotFound
import json
from urllib.parse import quote, unquote
from includes.userauth import *
from includes.api_auth import *
from includes.tasker import *
import hashlib

landing_page = Blueprint('landing_page', __name__, template_folder='templates')
login_page = Blueprint('login_page', __name__, template_folder='templates')
logout_page = Blueprint('logout_page', __name__, template_folder='templates')
userauth_page = Blueprint('userauth_page', __name__, template_folder='templates')
signup_page = Blueprint('signup_page', __name__, template_folder='templates')
useradd_page = Blueprint('useradd_page', __name__, template_folder='templates')
about_page = Blueprint('about_page', __name__, template_folder='templates')
youtube_operation = Blueprint('youtube_operation', __name__, template_folder='templates')

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
            # newlist - POST parameterized as name=cafebabe&desc=beefcode&access=PRIVATE&tracks=id-id-id-id
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
                    new_tracks = unquote(request.form.get('tracks')).split('-')
                ret_tuple = ytapi.new_playlist(playlist_name=new_name, desc=new_desc, tracks=new_tracks)
                if ret_tuple[0] == -1:
                    json_response['status'] = "fail"
                    json_response['message'] = "creation failed"
                    return json.dumps(json_response)
                elif ret_tuple[0] == -2:
                    json_response['status'] = "crash"
                    json_response['message'] = "crashed in creation"
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
            else:
                json_response['status'] = "fail"
                json_response['message'] = "unknown op"
                return json.dumps(json_response)
    else:
        abort(403)