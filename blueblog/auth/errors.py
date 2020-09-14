#-*- coding=utf-8 -*-

from flask import render_template

from blueblog.auth import auth_bp

@auth_bp.app_errorhandler(404)
def page_not_found(e):
    return render_template('404.html'),404

@auth_bp.app_errorhandler(500)
def internal_error(e):
    return render_template('500.html'),500