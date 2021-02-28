import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from random import randint
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user
from sqlalchemy import select
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/email')
def sendmamail():
    return render_template('email.html')

@auth.route('/logout')
def logout():
    return 'Logout'

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    rand = str(randint(1000, 9999))
    #file = open("text.txt", "w")
    #file.write(rand)
    mail = 'maksssav2012@gmail.com'
    sendmail(mail, rand)
    user = User.query.filter_by(email=email).first()

    if user:  # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))
    if user:
        return redirect(url_for('auth.signup'))

    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'), code=rand)

    db.session.add(new_user)
    db.session.commit()

    #coderandl = db.session.execute('select * from User')

    #coderand = db.session.query(User).filter(User.code.like(str(rand))).one()
    #cod = coderandl.fetchall()

    #file2 = open("text3.txt", "w")
    #file2.write(str(cod))

    #file1 = open("text1.txt", "w")
    #file1.write(str(coderand))
    return render_template('email.html')


def sendmail(addr_to, temp_pass):
    msg = MIMEMultipart()
    body = "Ваш авторизационный код " + str(temp_pass)
    msg['Subject'] = 'Временный пароль'
    msg.attach(MIMEText(body, 'plain'))
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login("YOUR EMAIL", "MAIL_PASS*****")
    server.sendmail("YOUR_EMAIL", addr_to, msg.as_string())
    server.quit()


@auth.route('/code', methods=['POST'])
def email_post():
    email = request.form.get('code')
    if(db.session.query(User).filter(User.code.like(str(email))).one()):
        return render_template('login.html')
    return render_template('email.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')

    remember = True if request.form.get('remember') else False
    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))
