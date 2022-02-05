from . import db
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .baze import User

userss = Blueprint('userss', __name__)

@userss.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')

        user = User.query.filter_by(login=login).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Вы успешно залогинились!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('userss.home'))
    return render_template("login2.html", user=current_user)

@userss.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('userss.login'))


@userss.route('/signup' , methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')

        user = User.query.filter_by(login=login).first()
        if user:
            flash('Данный пользователь уже зарегистрирован', category='error')
        else:
            new_user = User(login=login, password=generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Аккаунт создан!', category='success')
            return redirect(url_for('userss.home'))
    return render_template("sign_up2.html", user=current_user)

@userss.route('/', methods=['GET', 'POST'])
def vhod():
    if request.method == 'POST':
        answer = request.form.get('yorn')
        if answer == 'No':
            return redirect(url_for('userss.signup'))
        elif answer == 'Yes':
            return redirect(url_for('userss.login'))
        else:
            return 'Нет такого варианта ответа!!!'
    return render_template('vhod.html')

@userss.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        return redirect(url_for('userss.logout'))
    return render_template('homes.html')
