#-*- coding=utf-8 -*-


from flask_wtf import FlaskForm
from wtforms.validators import DataRequired,Length,Email,EqualTo,Regexp
from wtforms import StringField,SubmitField,BooleanField,PasswordField
from wtforms import ValidationError

from blueblog.models import User

class LoginForm(FlaskForm):
    email=StringField('Email',validators=[DataRequired(),Length(4,64),Email()])
    password=PasswordField('Password',validators=[DataRequired()])
    remember_me=BooleanField('Keep me logged in')
    submit=SubmitField('Log In')

class RegisterForm(FlaskForm):
    email=StringField('Email',validators=[DataRequired(),Length(4,64),Email()])
    username=StringField('UserName',validators=[DataRequired(),Length(1,128),
                           Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,
                                  'usernames must have only letters,numbers,dots or underscores')])
    password=PasswordField('Password',validators=[DataRequired(),
                EqualTo('confirm_password',message='Two password must match.')])
    confirm_password=PasswordField('Confirm Password',validators=[DataRequired()])
    submit=SubmitField('Register')

    def validate_email(self,field):
        exist_email=User.query.filter_by(email=field.data).first()
        if exist_email is not None:
            raise ValidationError('the email has been already exist')

    def validate_username(self,field):
        exist_username=User.query.filter_by(username=field.data).first()
        if exist_username is not None:
            raise ValidationError('the username has been already exist')


class ChangePasswordForm(FlaskForm):
    old_password=PasswordField('Old Password',validators=[DataRequired()])
    new_password=PasswordField('New Password',validators=[DataRequired(),
                    EqualTo('confirm_new_password',message='Two password must match.')])
    confirm_new_password=PasswordField('Confirm New Password',validators=[DataRequired()])
    submit=SubmitField('Change Password')

class ResetPasswordRequestForm(FlaskForm):
    email=StringField('Email',validators=[DataRequired(),Length(4,64),Email()])
    submit=SubmitField('Reset Password')


class ResetPasswordForm(FlaskForm):
    password= PasswordField('New Password',validators=[DataRequired(),
                    EqualTo('confirm_password',message='Two password must match.')])
    confirm_password=PasswordField('Confirm New Password',validators=[DataRequired()])
    submit = SubmitField('Reset Password')



class ChangeEmailForm(FlaskForm):
    email=StringField('New Email',validators=[DataRequired(),Email(),Length(4,64)])
    password=PasswordField('Password',validators=[DataRequired()])
    submit=SubmitField('Change Email')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('This email address has been exist.')


