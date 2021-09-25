import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
import app_config
import os

def gen_session_token(length=24):
    token = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(length)])
    return token

class User:
    def __init__(self, db, username, password, token=None, avatar='default.jpg'):
        self.db = db
        self.username = username
        self.password = password
        self.token = token
        self.avatar = avatar
        
    def get_avatar(self):
        return self.avatar
    
    def set_avatar(self, filename):
        self.avatar = filename
        self.db.users.update_one({"username": self.username}, {"$set" : {"avatar": filename}})

    @classmethod
    def new(cls, db, username, password):
        password = generate_password_hash(password)
        db.users.insert({"username": username, "password": password })
        return cls(db, username, password)
    
    @staticmethod
    def find_user(db, username):
        return len(list(db.users.find({"username": username}))) > 0
    
    @classmethod
    def get_user(cls, db, username):
        data = db.users.find_one({"username": username})
        return cls(db, data["username"], data["password"], data.get('token', None), data.get('avatar', 'default.jpg'))       


    def authenticate(self, password):
        return check_password_hash(self.password, password)
    
    def update_password(self, password):
        self.password = generate_password_hash(password)
        self.db.users.update_one({"username": self.username}, {"$set": {"password": self.password}})

    def init_session(self):
        self.token = gen_session_token()
        self.db.users.update_one({"username": self.username}, {"$set": {"token": self.token}})
        return self.token
    
    def authorize(self, token):
        return token == self.token
    
    def terminate_session(self):
        self.token = None
        self.db.users.update_one({"username": self.username}, {"$set": {"token": None}})
    
    def __str__(self):
        return f'{self.username};{self.password};{self.token}'
    