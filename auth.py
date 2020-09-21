from flask import Blueprint, render_template, redirect, url_for, request,flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from .models import User
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/')
def index():
    return render_template("index.html")

@auth.route('/login', methods=['POST','GET','OPTIONS'])
def login():
    # req = request.get_json()
    email = request.form['email']
    password =  request.form['password']
    print(email, password,"**************************888")
    user = User.query.filter_by(email=email).first()
    
    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        # flash('Please check your login details and try again.')
        # return redirect(url_for('auth.login')) 
        # if the user doesn't exist or password is wrong, reload the 
        print("_____-______________________________-")
        return redirect(url_for('auth.login'))
    # if the above check passes, then we know the user has the right credentials
    print(User,"+++++++++++++++++++++++++++++++")
    return redirect(url_for('auth.dashboard'))

@auth.route('/dashboard',methods=['POST','GET','OPTIONS'])
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