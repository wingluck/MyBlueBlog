#-*- coding=utf-8 -*-

from flask import render_template,url_for,redirect,flash,request
from flask_login import login_required,login_user,logout_user,current_user

from blueblog.auth import auth_bp
from blueblog.auth.forms import LoginForm,RegisterForm,ChangePasswordForm,ResetPasswordForm,ResetPasswordRequestForm,ChangeEmailForm
from blueblog.models import User
from blueblog import db
from blueblog.email import send_mail

#注册一个钩子函数，在每个请求之前调用
@auth_bp.before_app_request
def before_request():
    if current_user.is_authenticated and not current_user.confirmed \
        and request.blueprint !='auth'  and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))

@auth_bp.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth_bp.route('/login',methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()#判断用户是否在数据库中
        if user is not None and user.verify_password(form.password.data):
            login_user(user,form.remember_me.data)
            next=request.args.get('next')
            if next is None or next.startswith('/'):
                next= url_for('main.index')
            return redirect(next)
    return render_template('auth/login.html',form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logout.')
    return redirect(url_for('main.index'))


@auth_bp.route('/register',methods=['GET','POST'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        new_user=User(email=form.email.data.lower(),
                      username=form.username.data,
                      password=form.password.data)
        db.session.add(new_user)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        token=new_user.generate_confirmation_token()
        send_mail(to=form.email.data.lower(),subject='Confirm Your Account',
                  template='auth/email/confirm',user=new_user,token=token)
        flash('You have been registered a new account.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html',form=form)


@auth_bp.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        try:
            db.session.commit()
        except:
            db.session.rollback()
        flash('Your account has been confirmed.')
    else:
        flash('The confirmation link is invalid or has expired.')
    return render_template(url_for('main.index'))


@auth_bp.route('/confirm')
@login_required
def resend_confirmation():
    token=current_user.generate_confirmation_token()
    send_mail(to=current_user.email, subject='Confirm Your Account',
              template='auth/email/confirm', user=current_user, token=token)
    flash('You have been resent a confirmation email to your account.')
    return redirect(url_for('main.index'))


@auth_bp.route('/change_password',methods=['GET','POST'])
@login_required
def change_password():
    form=ChangePasswordForm()
    if form.validate_on_submit():
         if current_user.verify_password(form.old_password.data):
              current_user.password=form.new_password.data
              db.session.add(current_user)
              try:
                  db.session.commit()
                  flash('Your Password has been changed.')
              except:
                  db.session.rollback()
                  flash('Your Password has not been changed.')
              return redirect(url_for('main.index'))
         else:
             flash('Invalid password')
    return render_template('auth/change_password.html',form=form)
                
@auth_bp.route('/reset',methods=['GET','POST'])
def reset_password_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form=ResetPasswordRequestForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            token=user.generate_reset_password_token()
            send_mail(to=user.email,subject='Reset Your Account Password',
                      template='auth/email/reset_password', user=user, token=token)
            flash('An email with instrucions to reset your password has been sent to you.')
            return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html',form=form)


@auth_bp.route('/reset/<token>',methods=['GET','POST'])
def reset_password(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form=ResetPasswordForm()
    if form.validate_on_submit():
        if User.reset_password(token,form.password.data):
            try:
                db.session.commit()
                flash('Your password has been update.')
            except:
                db.session.rollback()
                flash('Your password has not been update successfully.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html',form=form)


@auth_bp.route('/change_email',methods=['GET','POST'])
@login_required
def change_email_request():
    form=ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email=form.email.data.lower()
            token=current_user.generate_change_email_token(new_email)
            send_mail(to=new_email,subject='Confirm Your Account Email Address',
                      template='auth/email/change_email', user=current_user, token=token)
            flash('A Confirm Email has been sent to your new email address,please login your email to confirm.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password')
    return render_template('auth/change_email.html',form=form)


@auth_bp.route('/change_email/<token>',methods=['GET','POST'])
@login_required
def change_email(token):
    if current_user.change_email(token):
        try:
            db.session.commit()
            flash('Your email address has been update.')
        except :
            db.session.rollback()
            flash('Your email address has not been update successfully.')
    else:
        flash('Invalid request')
    return redirect(url_for('main.index'))
        










