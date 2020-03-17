from flask import Flask, escape, request, render_template, url_for, flash, redirect, session
from flask_pymongo import PyMongo
from lib.crawling import Crawling
from lib.preprocessing import Preprocessing
from lib.vsm import VSM
from lib.svd import SVD
import bcrypt

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'test'
app.config["MONGO_URI"] = 'mongodb://localhost:27017/test'
mongo = PyMongo(app)

@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r

@app.route('/')
def index():
    # if 'username' in session:
    # flash ('Berhasil Registrasi')
    # flash('Kamu Berhasil Registrasi', 'success')
    # return 'username' + ' Berhasil Registrasi'
    return render_template('index.html')

@app.route('/summary')
def summary():

    return render_template('summary.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', username=session['username'])

@app.route('/login', methods=['POST'])
def login():
    users = mongo.db.users
    login_user = users.find_one({'name': request.form['username']})

    passwd = request.form['pass'].encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(passwd, salt)

    if login_user:
        # if bcrypt.hashpw(bytes(request.form['pass'], 'utf-8').decode('utf-8'), bytes(login_user['password'], 'utf-8').decode('utf-8')) == bytes(login_user['password'], 'utf-8').decode('utf-8'):
        if bcrypt.checkpw(passwd, hashed):
            # print("match")
            session['username'] = request.form['username']
            # return redirect(url_for('index'))
            return redirect(url_for('dashboard',username=session['username']))

        if 'username' in session:
            username = session['username']
        return redirect(url_for('dashboard', username=session['username']))

    return 'Invalid username/password combination'

    # return render_template('login.html')

# @app.route('/signin')
# def signin():

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        users = mongo.db.users
        existing_user = users.find_one({'name' : request.form['username']})

        if existing_user is None:
            passwd = request.form['pass'].encode('utf-8')
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(passwd, salt)
            users.insert({'name' : request.form['username'], 'password' : hashed})
            session['username'] = request.form['username']
            # return 'username' + ' Berhasil Registrasi'
            return redirect(url_for('index'))

        return 'That username already exsist!'

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/datring')
def datring():
    return render_template('datring.html',username=session['username'])

@app.route('/pengujian')
def pengujian():
    return render_template('pengujian.html',username=session['username'])


if __name__ == '__main__':
    app.secret_key = 'myscreet'
    app.run(debug=True)	
