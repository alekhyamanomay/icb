from flask import Blueprint, render_template, redirect, url_for, request,flash,make_response,jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from flask import current_app as app
from icb.models import User
from functools import wraps
from flask_jwt import jwt_required
# from jwt import verify_token
from .models import User
import jwt
from . import db

auth = Blueprint('auth', __name__)


def verify_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        """
        Decodes the auth token
        :param auth_token:
        :return: integer|string
        """
        print(request.args.get('token'))
        token = request.args.get('token')
        if not token:
            return jsonify({'message':"Missing token"}), 403
        try:
            payload = jwt.decode(token, app.config.get('SECRET_KEY'))
            return payload['sub']
        except :
            return jsonify({'message':"Invalid token"}), 403
        return func(*args,**kwargs)
    return wrapped

@auth.route('/')
def index():
    return render_template("index.html")

@auth.route('/login', methods=['POST','GET','OPTIONS'])
# @verify_token
def login():
    responseObject = {}
    # req = request.get_json()
    email = request.form['email']
    password =  request.form['password']
    # check if the user actually exists
    try:
        user = User.query.filter_by(email=email).first()

        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user or not check_password_hash(user.password, password):
            # flash('Please check your login details and try again.')
            return redirect(url_for('auth.login'))

        auth_token = user.encode_auth_token(user.id)
        print(auth_token)
        if auth_token:
            responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode('utf-8')
                    }
            return render_template('dashboard.html', result = responseObject['auth_token'])
            # return make_response(jsonify(responseObject)), 200
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Try again'
            }
        return make_response(jsonify(responseObject)), 500
        # if the above check passes, then we know the user has the right credentials
    

@auth.route('/dashboard',methods=['POST','GET','OPTIONS'])
@verify_token
def dashboard():
    return render_template("dashboard.html")

@auth.route('/monthpage')
def monthpage():
    return render_template("monthly.html")

@auth.route('/add_user')
def add_user():
    return "add_user"

@auth.route('/add_user', methods=['POST'])
def add_user_post():
    # print(request.get_data(),"*******"
    req = request.get_json()

    user = User.query.filter_by(email=req['email']).first()
    if user: 
        # flash('Email address already exists')
        return "added_user already"
        # return redirect(url_for('auth.add_user'))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(email=req['email'], name=req['name'], password=generate_password_hash(req['password'], method='sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()
    return "ready to login"
#   return render_template('add_user.html')

@auth.route('/logout')
def logout():
    logout_user()
    return 'Logout'

@auth.route('/update',methods=['POST'])
def update_user():
    req = request.get_json()
    update_user = User.query.filter_by(name= req['name']).first()
    if update_user:
        update_user.email = req['email']
        # update the new user to the database
        db.session.add(update_user)
        db.session.commit()
        return "Updated User"
    return "Failed to update user"

@auth.route('/delete',methods=['POST'])
def delete_user():
    req = request.get_json()
    delete_user = User.query.filter_by(name= req['name']).first()
    if delete_user:
        # update the new user to the database
        db.session.delete(delete_user)
        db.session.commit()
        return "User deleted"
    return "Failed to delete user"