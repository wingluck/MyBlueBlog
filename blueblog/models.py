#-*- coding=utf-8 -*-

from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from flask import current_app
from blueblog import db,login_manager


class Role(db.Model):
    __tablename__='roles'
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(40))

    def __repr__(self):
        return "<Role %s>" % self.name

class User(UserMixin,db.Model):
    __tablename__='users'
    id=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(64))
    username=db.Column(db.String(128),unique=True,index=True)

    password_hash=db.Column(db.String(128))
    #role_id = db.Column(db.Integer,db.ForeignKey('roles.id'))
    
    #增加一个confirmed字段，如果为True，表示用户已经通过邮件验证
    confirmed=db.Column(db.Boolean,default=False)


    @property
    def password(self):
        raise AttributeError('password is not readable attribute')

    @password.setter
    def password(self,password):
        self.password_hash=generate_password_hash(password)

    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

    def __repr__(self):
        return "<User %s>" % self.username

    #定义用户账户确认令牌生成函数
    def generate_confirmation_token(self,expiration=3600):
        s=Serializer(current_app.config['SECRET_KEY'],expiration)
        tmp_se=s.dumps({'confirm':self.id})  #生成一个加密的签名
        return tmp_se.decode('utf-8')    #因为dumps（）方法生成的签名类型为bytes，所以需要解码操作

    #定义用户确认令牌函数
    def confirm(self,token):
        s=Serializer(current_app.config['SECRET_KEY'])
        try:
            to_json=s.loads(token.encode('utf-8'))
        except:
            return False
        id=to_json.get('confirm')
        if id!=self.id:
            return False
        self.confirmed=True
        db.session.add(self)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        return True


#该函数用于从数据库获取指定标识符对应的用户时调用
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

