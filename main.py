from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from sqlalchemy import func, desc
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask import session as login_session
from werkzeug.utils import secure_filename
import random
import string
from db_setup import Base, User, Subject, Post
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import os
from flask import make_response
import requests

UPLOAD_FOLDER = '/vagrant/tutor_site/static/pictures/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Menu App"

engine = create_engine('sqlite:///localtutors.db')
Base.metadata.bind = engine
DBsession = sessionmaker(bind=engine)
session = DBsession()


def createUser(login_session):
    newUser = User(name=login_session.get('username'),
                   email=login_session.get('email'),
                   picture=login_session.get('picture'))
    session.add(newUser)
    session.commit()
    user = session.query(User).filter(
        User.email == login_session.get('email')).first()
    print 'User number %s created' % user.id
    return user


def checkForUser(login_session):
    user = session.query(User).filter(
        User.email == login_session.get('email')).first()
    return user


def getUser(email):
    user = session.query(User).filter(
        User.email == email).first()
    return user


def validateInput(title, description, rate):
    params = {}
    if not title or len(title) > 49:
        params['title'] = 'Field cannot be left empty and cannot ' \
            'be more than 50 characters'
    if not description:
        params['description'] = 'Field cannot be left empty'
    try:
        rate = int(rate)
    except:
        params['rate'] = 'Rate should be the dollar amount per hour you ' \
            'charge for tutoring. Do not include decimals.'
    return params


def deleteSessionData(login_session):
    del login_session['access_token']
    del login_session['provider']
    del login_session['provider_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']


def generate_form_token(login_session):
    form_token = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['form_token'] = form_token
    print 'generated form token'
    return form_token


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def delete_file(user):
    directory = '%s%s' % (app.config['UPLOAD_FOLDER'], user.id)
    print directory
    if os.listdir(directory):
        print 'folder is not empty'
        files = os.listdir(directory)
        for file in files:
            path = '%s/%s' % (directory, file)
            os.remove(path)


@app.route('/')
def main():
    user = checkForUser(login_session)
    subjects = session.query(Subject).order_by(Subject.name).all()
    return render_template('main.html',
                           user=user,
                           subjects=subjects)


@app.route('/tutors/<string:subject_name>')
def subjectView(subject_name):
    user = checkForUser(login_session)
    subjects = session.query(Subject).order_by(Subject.name).all()
    sub_id = session.query(Subject.id).filter(
        Subject.name == subject_name).first()
    posts = session.query(Post).filter(Post.subject_id == sub_id[0]).order_by(desc(Post.id)).all()

    return render_template('main.html',
                           user=user,
                           subjects=subjects,
                           posts=posts,
                           subject_name=subject_name)


@app.route('/newSubject', methods=['GET', 'POST'])
def newSubject():
    user = checkForUser(login_session)
    if not user:
        return redirect('/')
    if request.method == 'GET':
        form_token = generate_form_token(login_session)
        return render_template('newSubject.html',
                               user=user,
                               form_token=form_token)
    else:
        subject = request.form['subject']
        form_token = request.form['form_token']
        if not form_token or form_token != login_session.get('form_token'):
            abort(403)
        if subject and len(subject) < 100:
            subject = subject.replace(' ', '_').lower()
            entry = Subject(name=subject, user=user)
            session.add(entry)
            session.commit()
            return redirect('/')
        else:
            error = 'Field must be between 1 and 100 characters long'
            form_token = generate_form_token(login_session)
            return render_template('newSubject.html',
                                   user=user,
                                   error=error,
                                   form_token=form_token)


@app.route('/tutors/<string:subject_name>/<int:post_id>')
def postView(subject_name, post_id):
    user = checkForUser(login_session)
    post = session.query(Post).filter(Post.id == post_id).first()
    return render_template('post.html',
                           user=user,
                           post=post,
                           title=post.title)


@app.route('/tutors/<string:subject_name>/new', methods=['GET', 'POST'])
def newPost(subject_name):
    user = checkForUser(login_session)
    if user is None:
        print 'No logged in user found'
        return redirect(url_for('subjectView',
                                subject_name=subject_name))
    if request.method == 'GET':
        form_token = generate_form_token(login_session)
        params = {}
        return render_template('newPost.html',
                               subject_name=subject_name,
                               user=user,
                               params=params,
                               form_token=form_token)
    else:
        title = request.form['title']
        description = request.form['description']
        rate = request.form['rate']
        form_token = request.form['form_token']
        if not form_token or form_token != login_session.get('form_token'):
            abort(403)
        params = validateInput(title, description, rate)

        if params:
            form_token = generate_form_token(login_session)
            return render_template('newPost.html',
                                   subject_name=subject_name,
                                   user=user,
                                   params=params,
                                   title=title,
                                   description=description,
                                   rate=rate,
                                   form_token=form_token)

        subject_id = session.query(Subject.id).filter(
            Subject.name == subject_name).first()
        newPost = Post(title=title,
                       description=description,
                       rate=int(rate),
                       user=user,
                       subject_id=subject_id[0])
        session.add(newPost)
        session.commit()
        print 'new post added:'
        print newPost
        return redirect(url_for('subjectView',
                                subject_name=subject_name))


@app.route('/tutors/<string:subject_name>/<int:post_id>/edit',
           methods=['POST', 'GET'])
def editPost(subject_name, post_id):
    post = session.query(Post).filter(Post.id == post_id).first()
    user = checkForUser(login_session)
    if user is None or user.email != post.user.email:
        return redirect(url_for('postView',
                                subject_name=subject_name,
                                post_id=post_id))
    if request.method == 'GET':
        form_token = generate_form_token(login_session)
        params = {}
        return render_template('newPost.html',
                               user=user,
                               subject_name=subject_name,
                               params=params,
                               title=post.title,
                               description=post.description,
                               rate=post.rate,
                               form_token=form_token)
    else:
        title = request.form['title']
        description = request.form['description']
        rate = request.form['rate']
        form_token = login_session.get('form_token')
        if not form_token or form_token != login_session.get('form_token'):
            abort(403)
        params = validateInput(title, description, rate)
        if params:
            form_token = generate_form_token(login_session)
            return render_template('newPost.html',
                                   user=user,
                                   subject_name=subject_name,
                                   params=params,
                                   title=title,
                                   description=description,
                                   rate=rate,
                                   form_token=form_token)
        post.title = title
        post.description = description
        post.rate = rate
        session.commit()
        return redirect(url_for('postView',
                                subject_name=subject_name,
                                post_id=post_id))


@app.route('/tutors/<string:subject_name>/<int:post_id>/delete',
           methods=['POST', 'GET'])
def deletePost(subject_name, post_id):
    user = checkForUser(login_session)
    post = session.query(Post).filter(Post.id == post_id).first()
    if user is None or user.email != post.user.email:
        return redirect(url_for('postView',
                                subject_name=subject_name,
                                post_id=post_id))
    if request.method == 'GET':
        form_token = generate_form_token(login_session)
        return render_template('delete.html',
                               user=user,
                               post=post,
                               form_token=form_token)
    else:
        form_token = request.form['form_token']
        if form_token == login_session.get('form_token'):
            session.delete(post)
            session.commit()
            print user
            print subject_name
            return redirect(url_for('subjectView',
                                    subject_name=subject_name))
        else:
            abort(403)


@app.route('/tutors/<int:subject_id>/json')
def subjectPostsJson(subject_id):
    posts = session.query(Post).filter(subject_id == Post.subject_id).all()
    return jsonify(Posts=[p.serialize for p in posts])


@app.route('/tutors/subjects/json')
def subjectsJson():
    subjects = session.query(Subject).all()
    return jsonify(Subjects=[s.serialize for s in subjects])


@app.route('/login')
def login():
    # user = checkForUser(login_session)
    # return render_template('login.html', user=user)

    user = checkForUser(login_session)
    if user:
        print 'user is logged in as %s' % user.name
        state = None
    else:
        user = None
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        print 'state is %s' % state
    return render_template('login.html',
                           user=user,
                           STATE=state)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user = checkForUser(login_session)
    if not user:
        return redirect(url_for('main'))
    if request.method == 'GET':
        return render_template('profile.html',
                               user=user)
    else:
        file = request.files['picture']
        name = request.form['name']
        if name:
            user.name = name
            session.commit()
        if file:
            # if user does not select file, browser also
            # submit a empty part without filename
            if file.filename == '' or not allowed_file(file.filename):
                file_error = 'There was an error with the file. ' \
                    'Please select a .png, .jpeg, or .jpg file and try again.'
                return render_template('profile.html',
                                       user=user,
                                       file_error=file_error)
            else:
                delete_file(user)
                filename = secure_filename(file.filename)
                directory = app.config['UPLOAD_FOLDER'] + str(user.id)
                print directory
                if not os.path.exists(directory):
                    os.makedirs(directory)
                    print 'directory created'
                file.save(os.path.join(directory, filename))
                static_filename = 'pictures/%s/%s' % (user.id, filename)
                user.picture = url_for('static', filename=static_filename)
                session.commit()
        return redirect(url_for('main'))


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    print '8'
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    print code

    print '7'
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError, e:
        print e
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    print '6'
    # Check that the access token is valid.
    access_token = credentials.access_token
    print access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # h is simialr to a cursor
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    print '5'
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    print '4'
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    print 'logged in as %s' % login_session.get('username')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    print '3'
    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    # login_session['credentials'] = credentials
    login_session['provider_id'] = gplus_id
    login_session['provider'] = 'google'

    print '2'
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    print 'logged in as %s' % login_session['username']
    user = getUser(login_session['email'])
    if user is None:
        user = createUser(login_session)

    return redirect(url_for('main'))


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    print 'initialing fbconnect'
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_' \
        'exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
            app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['provider_id'] = data["id"]

    # The token must be stored in the login_session in order to
    # properly logout, let's strip out the information before the
    # equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s' \
        '&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    user = checkForUser(login_session)
    if user is None:
        user = createUser(login_session)

    return redirect(url_for('main'))


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        deleteSessionData(login_session)
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('main'))
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/logout')
def logoutUser():
    provider = login_session.get('provider')
    if not provider:
        return redirect(url_for('main'))
    if provider == 'facebook':
        return redirect(url_for('fbdisconnect'))
    elif provider == 'google':
        return redirect(url_for('gdisconnect'))


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['provider_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')
    print 'Status of logout is %s' % result[0]['status']
    if result[0]['status']:
        deleteSessionData(login_session)
        return redirect(url_for('main'))
    else:
        return "failed to log out user"


@app.route('/listall')
def listAll():
    user = checkForUser(login_session)
    if user:
        username = user.name
    else:
        username = None
    subjects = session.query(Subject).all()
    posts = session.query(Post).all()
    users = session.query(User).all()
    return render_template('listall.html',
                           subjects=subjects,
                           posts=posts,
                           users=users,
                           username=username,
                           login_session=login_session)


if __name__ == '__main__':
    app.secret_key = 'something'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
