#-*- coding=utf-8 -*-

from flask import render_template,url_for,redirect

from blueblog.auth import auth_bp
from blueblog.forms import LoginForm


@auth_bp.route('/login')
def login():
    form=LoginForm()
    return render_template('auth/login.html',form=form)




