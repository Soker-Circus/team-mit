from flask import Flask, render_template, redirect, url_for, request, jsonify, session
from flask import make_response
import os.path
import os
import json
import re
import requests
from datetime import datetime
from flask_cors import CORS
import random
import urllib.request
from urllib.parse import urlparse
from functools import wraps
from authlib.integrations.flask_client import OAuth
# from decouple import config
from werkzeug.utils import secure_filename
import pymongo
from pymongo import MongoClient

app = Flask(__name__)

app.secret_key = 'enjaamiFennelda$S'

oauth = OAuth(app)

cors = CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SESSION_ID_KEY = "sid"

UPLOAD_FOLDER = 'static/uploads/'

cluster = MongoClient('mongodb+srv://prakash-1211:prakash@cluster0.enw9p.mongodb.net/myFirstDatabase?retryWrites=true&w=majority')

db = cluster["teamit"]

def is_session_valid():

    if(SESSION_ID_KEY in session):
        return True

    return False


def get_sid():

    return session.get(SESSION_ID_KEY, None)


def get_userid():

    return session.get("user_id", None)


@app.route('/', methods=['GET', 'POST'])
def page_index():
    logged_in = is_session_valid()
    # tlogger.info("logged_in", logged_in)
    return render_template(
        'index.html', logged_in=logged_in
    )

@app.route('/login', methods=['GET'])
def page_login_get():

    if(is_session_valid()):

        user_id = get_userid()
        
        resp = make_response(redirect(url_for('page_feature_get')))
        resp.set_cookie('user_id', str(user_id))
        return resp
    
    return render_template(
        'login.html'
    )

from flask_bcrypt import Bcrypt

import base64
import binascii

bcrypt = Bcrypt()

def hash_password(password):

    return bcrypt.generate_password_hash(password)

def match_password(db_password, password):

    return bcrypt.check_password_hash(db_password, password)

def encode_base(message):
    
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message

def decode_base(base64_message):

    
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')
   
    return message

@app.route('/signup', methods=['POST'])
def page_signup_post():

    col = db["user_details"]

    username  = request.values.get('username')
    email     = request.values.get('email')
    password  = request.values.get('password')
    user_role = request.json['user_role']

    logged_in = is_session_valid()

    hashpass        = hash_password(password)

    existing_user = get_user_by_email(email)

    if existing_user:

        return "user already exists"
    
    user_dict = {
        "username" : username,
        "email"    : email,
        "password" : hashpass,
        "user_role": user_role,
    }

    col.insert_one(user_dict)

    return True

@app.route('/get/user/details', methods=['GET'])
def get_user_details_ui():

    user_details = get_user_details()

    return render_template("user-details.html", user_details = user_details)

def get_user_by_email(email):

    col = db["user_details"]

    user_dict = {
        "email" : email
    }

    user_obj = col.find_one(user_dict)

    return user_obj


def get_user_details():

    col = db["user_details"]

    user_id = get_userid()

    s_id = get_sid()

    user_details = col.find_one({"user_id":int(user_id)},{"_id":False,"password":False})

    return user_details