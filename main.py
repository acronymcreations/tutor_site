from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy import func
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask import session as login_session
import random
import string
from db_setup import Base, User, Subject, Post
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)

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


def getUserID(email):
    user = session.query(User).filter(
        User.email == email).first()
    return user


@app.route('/')
def main():
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

    subjects = session.query(Subject).all()
    return render_template('main.html',
                           user=user,
                           subjects=subjects,
                           STATE=state)


@app.route('/tutors/<string:subject_name>')
def subjectView(subject_name):
    user = checkForUser(login_session)
    subjects = session.query(Subject).all()
    sub_id = session.query(Subject.id).filter(
        Subject.name == subject_name).first()
    posts = session.query(Post).filter(Post.subject_id == sub_id[0]).all()

    return render_template('main.html',
                           user=user,
                           subjects=subjects,
                           posts=posts)


@app.route('/tutors/<string:subject_name>/<int:post_id>')
def postView(subject_name, post_id):
    user = checkForUser(login_session)
    post = session.query(Post).filter(Post.id == post_id).first()
    return render_template('post.html',
                           user=user,
                           post=post)


@app.route('/tutors/<string:subject_name>/new', methods=['GET','POST'])
def newPost(subject_name):
    if request.method == 'GET':
        user = checkForUser(login_session)
        if user is None:
            print 'No logged in user found'
            return redirect(url_for('subjectView',
                                    subject_name=subject_name))
        else:
            print 'Found %s as logged in user' % user.name
            return render_template('newPost.html',
                                   subject_name=subject_name,
                                   user=user)
    else:
        user = checkForUser(login_session)
        if user is None:
            return redirect(url_for('subjectView',
                                    subject_name=subject_name))
        else:
            description = request.form['description']
            rate = request.form['rate']
            subject = request.form['subject']

            newPost = Post(description=description,
                           rate=rate,
                           subject=subject,
                           user=user)
            session.add(newPost)
            session.commit()
            print 'new post added:'
            print newPost
            return redirect(url_for('subjectView',
                                    subject_name=subject_name))


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
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id
    print login_session['access_token']
    print login_session['credentials']
    print login_session['gplus_id']

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
    userId = getUserID(login_session['email'])
    if userId is None:
        userId = createUser(login_session)

    return redirect(url_for('main'))


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session.get('username')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


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
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
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
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


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
                           username=username)







if __name__ == '__main__':
    app.secret_key = 'something'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
