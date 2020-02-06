from flask import Blueprint, render_template, session, flash, request, redirect, url_for, current_app
from models import *
from database import db_session
from datetime import datetime, timedelta
from functools import wraps
import settings


auth = Blueprint('auth', __name__,
                 template_folder='templates/auth')

def logged_user():
    if not settings.online:
        return db_session.query(User).filter_by(name="local").first()
    if 'logged_user_id' in session.keys():
        return db_session.query(User).get(session['logged_user_id'])

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if settings.online and not is_logged():
            return redirect(url_for('auth.login') + '?next=' + request.url)
        return f(*args, **kwargs)
    return decorated_function


def group_required(*groups):
    def real_decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if settings.online and not is_in_group(groups):
                return 'Acesso não permitido.'
            return f(*args, **kwargs)
        return decorated_function
    return real_decorator


def is_logged():
    if ('logged_user_id' not in session) or ((datetime.now() - session['last_authentication']) > settings.session_duration):
        return False
    return True


def is_in_group(groups):
    grupo = db_session.query(Group).filter(Group.username.in_(groups), Group.users.any(
        User.id == logged_user().id)).first()
    if grupo:
        return True
    return False

def is_password_secure(pw):
    if pw != "808452":
        return True
    return False


@auth.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        user = authenticate(username, password)
        if user:
            if is_password_secure(password):
                return redirect(request.args.get("next"))
            else:
                flash("A senha não atende aos critérios de segurança. Modifique-a.", 'alert-warning')
                return render_template("change-password.html", user=user)
        else:
            flash("Usuário ou senha inválida", 'alert-danger')
    if 'next' in request.args:
        return render_template("login.html", next=request.args['next'])
    else:
        return render_template("login.html")


@auth.route("/logout")
def logout():
    session.clear()
    return render_template("login.html", next=url_for("views.index"))


@auth.route("/change-password")
def change_password():
    return render_template("change-password.html")


@auth.route("/change-password", methods=['POST'])
def change_password_post():
    user = db_session.query(User).get(request.form['userid'])
    if not is_password_secure(request.form['new-password']): 
        flash("A senha não atende aos critérios de segurança. Modifique-a.", 'alert-warning')
        return render_template("change-password.html", user=user)
    erro = False
    if not user.check_password(request.form['current-password']):
        flash("Senha não confere", 'alert-danger')
        return render_template("change-password.html", user=user)
    if request.form['new-password'] != request.form['password-confirm']:
        flash("Confirmação da senha não confere", 'alert-danger')
        return render_template("change-password.html", user=user)
    user.set_password(request.form['new-password'])
    db.session.add(user)
    db.session.commit()
    flash("Senha alterada com sucesso", "alert-success")
    return render_template("login.html", next=url_for("views.index"))


def authenticate(username, password):
    user = db_session.query(User).filter_by(username=username).first()
    if user and user.check_password(password) and user.active:
        session['logged_user_id'] = user.id
        session['last_authentication'] = datetime.now()
        return user
