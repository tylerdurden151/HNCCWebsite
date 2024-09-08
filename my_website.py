"""SDEV 300 6381
Assignment: Lab 8
Name: Timothy Eckart
Date: 9 Jul 2024"""

import re
from datetime import datetime
import os

import db
from flask import Flask, render_template, url_for, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.secret_key = "SDEV"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'logger.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class Users(db.Model): # pylint: disable=too-few-public-methods
    """
    This function is the database to store the usernames and passwords
    :return:
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))

    def __init__(self, username, password):
        self.username = username
        self.password = password

class Logger(db.Model): # pylint: disable=too-few-public-methods
    """
    This function is the database to store the failed login
    attempts
    """
    id = db.Column(db.Integer, primary_key=True)
    datetime = db.Column(db.DateTime)
    ipaddress = db.Column(db.String(100))

    def __init__(self, timestamp, ipaddress):
        self.datetime = timestamp
        self.ipaddress = ipaddress



with app.app_context():
    db.create_all()

def new_password_check(new_password):
    """
    This function is to check the new users password
    :return: pass value to update password function
    """
    if len(new_password) < 12:
        return False
    if not re.search("[a-z]", new_password):
        return False
    if not re.search("[A-Z]", new_password):
        return False
    if not re.search("[0-9]", new_password):
        return False
    if not re.search("[_@$]", new_password):
        return False
    return True
def password_check(user_pass):
    """
    This function is to check the users password
    :return: pass value to registration function
    """
    if len(user_pass) < 12:
        return False
    if not re.search("[a-z]", user_pass):
        return False
    if not re.search("[A-Z]", user_pass):
        return False
    if not re.search("[0-9]", user_pass):
        return False
    if not re.search("[_@$]", user_pass):
        return False
    return True


def common_password(new_password):
    """
    This function is to check the
    passwords and see if they match
    the Common Password .txt
    :return:
    """
    with open('CommonPassword.txt', 'r', encoding='utf-8') as file:
        common_passwords = file.read().splitlines()
    if new_password in common_passwords:
        return False
    return True

def time_display():
    """
    This function is to display on the html the
    current date and time
    :return: current date and time
    """
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return current_time


@app.route("/")
def home():
    """
    This function is to make the home page for the website
    :return: home page value of index.html
    """
    return render_template("index.html", time=time_display())


@app.route("/about")
def about():
    """
    This function is to make the about page for the website
    :return: about page value of index.html
    """
    return render_template("about.html", time=time_display())


@app.route("/contact")
def contact():
    """
    This function is to make the contact page for the website
    :return: about page value of index.html
    """
    return render_template("contact.html", time=time_display())


@app.route("/update_password", methods=["POST", "GET"])
def update_password():
    """
    This function is to make the Password update page for the website
    :return: about page value of update_password.html
    """
    if request.method == "POST":
        email = request.form["email"]
        if email is None:
            name_error = "Your Username does not meet the complexity requirements."
            return render_template("registration.html", error=name_error)
        update_user = Users.query.filter_by(username=email).first()
        old_password = request.form.get("old_password_from_form")
        new_password = request.form.get("password")
        if update_user and check_password_hash(update_user.password, old_password):
            session["user"] = email
            if not new_password_check(new_password):
                error = "Your password does not meet the complexity requirements."
                return render_template("update_password.html", error=error)
            if not common_password(new_password):
                common_error = "Your password is too simple, try again."
                return render_template("update_password.html", error=common_error)
            hashed_password = generate_password_hash(new_password)
            update_user.password = hashed_password
            db.session.add(update_user)
            db.session.commit()
            flash('New Password successfully added')
            return redirect(url_for("user"))
        else:
            old_error = "Your password does not match the database records."
            return render_template("update_password.html", error=old_error)
    return render_template("update_password.html", time=time_display())



@app.route("/login", methods=["POST", "GET"])
def login():
    """
    This function is to make the login page for the website
    :return: redirect to display user function
    """
    if request.method == "POST":
        email = request.form["email"]
        password = request.form.get("password")
        log_user = Users.query.filter_by(username=email).first()
        if log_user and check_password_hash(log_user.password, password):
            session["user"] = email
            return redirect(url_for("user"))
        else:
            log_time = datetime.now()
            ip_address = request.remote_addr
            new_log = Logger(log_time, ip_address)
            db.session.add(new_log)
            db.session.commit()
            flash('No account found.')
            return render_template("login.html")
    else:
        return render_template("login.html", time=time_display())


@app.route("/user")
def user():
    """
    This function is to make the user's page for the website
    :return: redirect to display hello user's name
    """
    if "user" in session:
        user_account = session["user"]
        return render_template("user.html", user=user_account, time=time_display())
    return redirect(url_for("login"))


@app.route("/registration", methods=["POST", "GET"])
def registration():
    """
    This function is to make the registration page for the website
    :return: about page value of index.html
    """
    server = request.form.get("server")
    added_user = request.form.get("user")
    if added_user is None or server is None:
        name_error = "Your Username does not meet the complexity requirements."
        return render_template("registration.html", error=name_error)
    username = added_user + "@" + server
    existing_user = Users.query.filter_by(username=username).first()
    if existing_user:
        already_exist = "Username already exist, try again."
        return render_template("registration.html", error=already_exist)
    user_pass = request.form.get("password")
    if not password_check(user_pass):
        error = "Your password does not meet the complexity requirements."
        return render_template("registration.html", error=error)
    hashed_password = generate_password_hash(user_pass)
    new_user = Users(username, hashed_password)
    db.session.add(new_user)
    db.session.commit()
    flash('New Account succesfully added')
    return render_template("registration.html", time=time_display())


if __name__ == "__main__":
    app.run(debug=True)
