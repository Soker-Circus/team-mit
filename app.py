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
from flask_pymongo import PyMongo,pymongo
from flask_mongoengine import MongoEngine
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os
import logging

# DB import
from flask_pymongo import PyMongo,pymongo

# from business.scheduler_handler import 
from flask_apscheduler import APScheduler
# scheduler methods import
import time
from flask import Blueprint

api = Blueprint('featurepreneur_api_bp', __name__)

app = Flask(__name__)

app.register_blueprint(api)


app.config["MONGO_URI"] = "mongodb+srv://prakash-1211:prakash@cluster0.enw9p.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"


app.config['MONGODB_SETTINGS'] = {
    'db': 'teamit',
    'host': app.config["MONGO_URI"]
}

mongo = PyMongo(app)
bcrypt = Bcrypt()
CORS(app)


scheduler = APScheduler()
scheduler.init_app(app)

mongo  = PyMongo(app)

# Setup Mongo Engine
db = MongoEngine()
db.init_app(app)

app.secret_key = 'enjaamiTale$eFennelda$S'
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

    user_id = get_userid()
    # tlogger.info("logged_in", logged_in)
    return render_template(
        'index.html', logged_in=logged_in,user_id = user_id
    )

@app.route('/login', methods=['GET'])
def page_login_get():

    if(is_session_valid()):

        user_id = get_userid()
        
        resp = make_response(redirect(url_for('page_index')))
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


F13R_SALT           = "ontea_tct_pullakai"
EXPIRE_TIME_MINUTES = 20

VALID_SESSION      = 0
BROKEN_SESSION_ID  = 1
SESSION_EXPIRED    = 2
IP_MISMATCH        = 3
USERID_MISMATCH    = 4
INVALID_SESSION_ID = 5

import socket

def get_ip():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    return ip

import datetime
import time

def get_current_time_millis():

    millis = int(round(time.time() * 1000))

    return millis

def get_session_base(userid):
    
    # sessionid format: ip_userid_expireat_salt

    ip = get_ip()
    current_time_millis = get_current_time_millis()
    expire_time_millis = current_time_millis + (EXPIRE_TIME_MINUTES * 60 * 1000)

    session_base = ip + '_' + str(userid) + '_' + str(expire_time_millis) + '_' + F13R_SALT 
    session_base_end = encode_base(session_base)

    return session_base_end

def validate_sessionid(sid):
    """
        Session Format:
        ip_userid_expireat_salt

        result:
        0 - valid session
        1 - broken session id
        2 - sessoin expired
        3 - ip mismatch
        4 - userid mismatch
        5 - invalid session id

    """

    if(sid is None):
        return False, INVALID_SESSION_ID

    decoded_session_id = decode_base(sid)

    # 1 - broken session id
    if(not decoded_session_id):
        return False, BROKEN_SESSION_ID

    # 1 - broken session id
    if('_' not in decoded_session_id):
        return False, BROKEN_SESSION_ID

    session_parts = decoded_session_id.split('_')

    userid = int(session_parts[1])

    # 4 - userid mismatch
    # TODO: Please fix this later
    '''
    if(userid != SAMPLE_USERID):
        return False, USERID_MISMATCH
    '''

    session_userip = session_parts[0]

    # 3 - ip mismatch
    ip = get_ip()
    if(session_userip != ip):
        return False, IP_MISMATCH

    # check session whether it is expired or not
    future_expire_millis = int(session_parts[2])
    current_time_millis =get_current_time_millis()

    seconds_left = (future_expire_millis - current_time_millis) / 1000

    # 2 - sessoin expired
    if(seconds_left < 0):
        return False, SESSION_EXPIRED

    return True, VALID_SESSION


def created_sessionid(userid):

    return get_session_base(userid)

def get_userid_from_sid(sid):

    decoded_session_id = decode_base(sid)

    session_parts = decoded_session_id.split('_')

    userid = int(session_parts[1])

    return userid
    

def login_user(username,password):
    col = db["user_details"]
    user_creds = col.find_one({"email" : username})

    if (user_creds is None):
        return "user does not exist"
    

    if (not match_password(user_creds['password'], password)):
        return "invalid password"
    
    user_id           = user_creds['user_id']
    user_name         = user_creds['username']
    authenticated     = 'Authentication successful'
    session['userid'] = user_creds['user_id']
    is_mentor          = user_creds["user_role"]


    sid = created_sessionid(user_id)

    result_dict = {
        "username" : user_name,
        "user_id" : user_id,
        "user_role" : is_mentor,
        "authenticated" : authenticated,
        "sid" : sid
    }

    return result_dict

@app.route('/logout', methods=['GET'])
def page_logout_get():

    if(SESSION_ID_KEY in session):
        del session[SESSION_ID_KEY]

    resp = make_response(redirect(url_for('page_login_get')))

    resp.set_cookie('user_id', '', expires=0)

    return resp

@app.route('/login', methods=['POST'])
def page_login_post():

    username    = request.values.get('email')
    password    = request.values.get('password')
    result_json = login_user(username, password)
    logged_in   = is_session_valid()

    session[SESSION_ID_KEY] = result_json['sid']
    session["user_id"]      = result_json['user_id']
    result                  = result_json

    user_id = get_userid()
    try:
        session['redirect_url'] = "/"
        resp = make_response(redirect(session["redirect_url"]))
    except:
        resp = make_response(redirect(url_for('/')))

    resp.set_cookie('user_id', str(user_id))
   
    return resp

def get_last_user_id():

    col = db["user_details"]

    last_user_id      = col.find().sort([('user_id',-1)]).limit(1)

    try:
        last_user_id = last_user_id[0]['user_id']
    except:
        last_user_id = 0

    # user_id = last_user_id + 1

    return last_user_id

@app.route('/signup', methods=['POST'])
def page_signup_post():

    col = db["user_details"]

    username  = request.values.get('username')
    email     = request.values.get('email')
    password  = request.values.get('password')
    user_role = request.values.get('user_type')

    user_id = get_last_user_id()

    new_user_id = user_id + 1


    logged_in = is_session_valid()

    hashpass        = hash_password(password)

    existing_user = get_user_by_email(email)

    if existing_user:

        return "user already exists"
    
    user_dict = {
        "user_id"  : new_user_id,
        "username" : username,
        "email"    : email,
        "password" : hashpass,
        "user_role": user_role,
    }

    col.insert_one(user_dict)

    return "True"


@app.route('/signup', methods=['GET'])
def page_signup_get():

    return render_template(
        'sign_up.html'
    )

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

def get_recent_links():

    col1 = db["lp_collection"]
    col2 = db["user_details"]

    links = []
    count = 1
    # .sort([('la_id', -1)]).limit(1)
    docs = list(col1.find({'isPrivate': False}).sort(
        [('created_at_timestamp', -1)]).limit(5))
    for doc in docs:
        del doc["_id"]
        user_deets = col2.find_one({"user_id": int(doc["user_id"])})
        doc["username"] = user_deets["username"]
        doc["username"] = doc["username"].split('@')[0]
        # #print(doc)
        if count > 5:
            break
        links.append(doc)
        count += 1
    return links

def get_top_contributors():
    col1 = db["lp_collection"]
    col2 = db["user_details"]
    pipeline = [
        {"$group": {'_id': '$user_id', 'count': {'$sum': 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}

    ]
    cursor = col1.aggregate(pipeline)
    data = []
    for doc in cursor:
        # del doc["_id"]
        # #print("true:",doc)
        # #print("doc",doc["_id"])
        user_details = col2.find_one({"user_id": int(doc["_id"])})
        doc["username"] = user_details["username"].split('@')[0]
        email = user_details["email"].split('@')[0]
        # #print(email)
        doc["formatted_username"] = ""
        for i in email.split('.'):
            doc["formatted_username"] += i
        # #print(doc)

        data.append(doc)
    return data

def get_formatted_username(user_id):
    col = db["user_details"]
    user_details = col.find_one({ "user_id" : int(user_id)})
    
    email = user_details["email"].split('@')[0]

    formatted_username = ""
    for i in email.split('.'):
        formatted_username+=i
    
    return formatted_username

@app.route('/la/dashboard', methods=["GET"])
def la_dashboard():
    if(is_session_valid()):
        ## get_recent_links and get_top_contributors

        recent_links = get_recent_links()
        top_contributors = get_top_contributors()

        if recent_links:
            recent_links = recent_links
        if top_contributors:
            top_contributors = top_contributors
        user_id = get_userid()
        logged_in = is_session_valid()

        data = {
            "user_id": int(user_id),
            "page_size": 100,
            "ltype": None,
            "_id": None
        }
        # result = fpr_business.la_get_user_articles(data)
        results = get_formatted_username(get_userid())

        # result1 = fpr_business.la_get_all_contributors()
        return render_template('learning-analytics-dashboard.html', context={'name': "TACT ADMIN"}, username=results, recent_links=recent_links, top_contributors=top_contributors, user_id=user_id, logged_in=logged_in)
    return render_template(
        'login.html'
    )

def get_all_contributors():
    col = db["lp_collection"]
    col2 = db["user_details"]
    pipeline = [
        {'$group': {"_id": "$user_id", "count": {"$sum": 1}}},
        {'$sort': {"count": 1}}
    ]
    cursor = col.aggregate(pipeline)
    col = 0
    data = []
    temp = []
    for doc_ in cursor:
        user_details = col2.find_one({"user_id": int(doc_["_id"])})
        username = user_details["username"].split('@')[0]
        email = user_details["email"].split('@')[0]

        doc_["username"] = username
        doc_["formatted_username"] = ""

        for i in email.split('.'):
            doc_["formatted_username"] += i
        if col > 2:
            data.append(temp)
            temp = []
            temp.append(doc_)
            col = 1
            continue
        temp.append(doc_)
        col += 1
    if col <= 3 and temp != []:
        data.append(temp)
    return data

from bson import json_util, ObjectId

def get_data_id(da):  # for pagination
    page_size = da["page_size"]
    user_id   = da["user_id"]
    try:
        ltype= da["ltype"]
    except:
        ltype=None
    try:
        _id= da["_id"]
    except:
        _id=None
    col1 = db["user_details"]
    col2 = db["lp_collection"]
    user_details = col1.find_one({"user_id": int(user_id)})
    username = user_details["email"].split('@')[0]
    if ltype == 'prev':
        cursor = col2.find(
            {'user_id': user_id, '_id': {'$gt': ObjectId(_id)}}).sort('_id', 1).limit(page_size)
        data = []
        for doc in cursor:
            data.append(json.loads(json_util.dumps(doc)))
        data = data[-1::-1]
        if not data:
            cursor = col2.find(
                {'user_id': user_id}).sort('_id', -1).limit(page_size)
            data = []
            for doc in cursor:
                data.append(json.loads(json_util.dumps(doc)))
            return data, data[0]['_id'], data[-1]['_id'], username
        else:
            return data, data[0]['_id'], data[-1]['_id'], username
    else:
        if _id is None and ltype is None:
            cursor = col2.find(
                {'user_id': user_id}).sort('created_at_timestamp', -1).limit(page_size)
        else:
            cursor = col2.find(
                {'user_id': user_id, '_id': {'$lt': ObjectId(_id)}}).sort('created_at_timestamp', -1).limit(page_size)

        data = []
        date_ordered = {}
        date_list = []
        for doc in cursor:
            data.append(json.loads(json_util.dumps(doc)))
            del doc["_id"]
            d = doc["updated_at"].split("-")
            # #print("csc",doc["updated_at"])
            from datetime import datetime

            doc["updated_at"] = datetime(int(d[0]), int(d[1]), int(d[2])).strftime("%A, %d %B %Y")

            # #print("first_date",first_date)

            try:
                date_list[date_ordered[doc["updated_at"]]].append(doc)
            except KeyError:
                date_list.append([doc])

                date_ordered.update(
                    {doc["updated_at"]: date_list.index([doc])})
            # #print("-------")
            # pprint.p#print(date_ordered)
            # pprint.p#print(date_list)

            # #print(data)
        if not data:
            cursor = col2.find(
                {'user_id': user_id}).sort('_id', -1).limit(page_size)
            data = []
            for doc in cursor:
                data.append(json.loads(json_util.dumps(doc)))
            try:
                result_dict = {
                    "data": data,
                    "start_id": data[0]['_id'],
                    "last_id": data[-1]['_id'],
                    "username": username

                }
                return result_dict
            except:
                result_dict = {
                    "data": data,
                    "start_id": None,
                    "last_id": None,
                    "username": username

                }
                return result_dict
        else:
       
            
            result_dict = {
                    "data": date_list,
                    "start_id": str(data[0]['_id']),
                    "last_id": str(data[-1]['_id']),
                    "username": username

                }
            return result_dict

@app.route('/la/contributors', methods=["GET"])
def la_contributors():

    result = get_all_contributors()
    logged_in = is_session_valid()
    if logged_in:
        user_id = get_userid()
        data = {
            "user_id": int(user_id),
            "page_size": 100,
            "ltype": None,
            "_id": None
        }
        results = get_data_id(data)

        return render_template('learning-analytics-contributors.html', data=result, logged_in=logged_in, username=results["username"])
    return render_template('learning-analytics-contributors.html', data=result, logged_in=logged_in)

def get_total_score_for(username_to_search):
    col1 = db["user_details"]
    col2 = db["lp_collection"]
    user = col1.find_one({"$or": [{"username": {
        "$regex": username_to_search,
        '$options': 'i'
    }},  {"email": {
        "$regex": username_to_search,
        '$options': 'i'
    }}]})
    username = user["username"].split('@')[0]
    profile_pic_link = user["profile_pic_link"]
    entries = list(col2.find(
        {"user_id": int(user["user_id"])}))
    count = len(entries)
    # for entry in entries:
    #     count+=1
    result_dict = {
        "username": username,
        "score": count,
        "user_id":  user["user_id"],
        "profile_pic_link": profile_pic_link
    }
    return result_dict

@app.route('/la/profile/<username>', methods=["GET"])
def la_profile(username):

    final_username = ""
    for i in username:
        final_username = final_username+".*"+i

    final_username = final_username.lower()

    data = {
        "username": final_username,
    }

    result = get_total_score_for(final_username)
    user_id = result["user_id"]
    data = {
        "user_id": int(user_id),
        "page_size": 100,
        "ltype": None,
        "_id": None
    }
    result1 = get_data_id(data)
    try:
        results = get_formatted_username(get_userid())
        logged_in = is_session_valid()
        return render_template('learning-analytics-profile.html', user_id=user_id, data=result, username=results, result=result1["data"], logged_in=logged_in)
    except Exception as e:
        logged_in = is_session_valid()

        return render_template('learning-analytics-profile.html', user_id=user_id, data=result, result=result1["data"], logged_in=logged_in)

def la_get_user_tags(user_id):
    col1 = db["lp_tags"]
    col2 = db["lp_collection"]
    la_tags = col1.find()

    user_la_tags_list = []
    tag_list = []
    # tag_id_list = []

    tag_ids = col2.find({"user_id": int(user_id)})

    for tag_id in tag_ids:
        # #print(tag_id)
        # #print(tag_id["tag_ids"])

        for id in tag_id["tag_ids"]:
            tag_list.append(id)

    for la_tag in la_tags:
        if int(la_tag["la_tag_id"]) in tag_list:

            user_la_tags_list.append(la_tag["la_tag"])

    return user_la_tags_list


@app.route('/la/<username>/articles', methods=["GET"])

def user_articles(username):

    final_username = ""
    for i in username:
        final_username = final_username+".*"+i

    final_username = final_username.lower()
    final_username = final_username.replace(" ", "")

    data = {
        "user_id": get_userid(),
        "page_size": 100,
        "ltype": None,
        "_id": None
    }
    all_tags = la_get_user_tags(data["user_id"])
    all_tags = all_tags
    result = get_data_id(data)
    return render_template('learning-analytics-user_articles.html', data=result['data'], username=result["username"], tags=all_tags)


@app.route('/la/user-articles/links/<user_id>', methods=["GET"])
def la_contributor_articles(user_id):

    data = {
        "user_id": int(user_id),
        "page_size": 100,
        "ltype": None,
        "_id": None
    }

    result = get_data_id(data)

    return render_template('learning-analytics-user_links.html', data=result["data"], username=result["username"])


@app.route('/la/make_link_private', methods=["POST"])

def la_make_link_private():

    title = request.form.get('title')
    user_id = get_userid()

    # result = akon.update_tech_links(data)
    data = {
        "user_id": user_id,
        "title": title
    }

    # return video_title

    result_json = make_article_link_private(user_id,title)

    return redirect(
        '/la/dashboard'
    )

def make_article_link_private(user_id, article_title):
    col1 = db["lp_collection"]
    query = {'user_id': int(user_id), 'title': article_title}
    # #print("checkingg",f12_la_collection_van.find_one(query))
    article = col1.update_one(
        query, {'$set': {'isPrivate': True}})
    return True


def make_article_link_public(user_id, article_title):
    col1 = db["lp_collection"]
    query = {'user_id': user_id, 'title': article_title}
    article = col1.update_one(
        query, {'$set': {'isPrivate': False}})
    return True


@app.route('/la/mylist/make_link_private', methods=["POST"])

def la__mylist_make_link_private():

    title = request.form.get('title')
    user_id = get_userid()

    # result = akon.update_tech_links(data)
    

    result_json = make_article_link_private(user_id,title)
    data = {
        "user_id": int(user_id),
        "page_size": 100,
        "ltype": None,
        "_id": None
    }

    result = get_data_id(data)

    username = result["username"]

    return redirect(
        f'/la/{username}/articles'
    )


@app.route('/la/mylist/make_link_public', methods=["POST"])

def la__mylist_make_link_public():

    title = request.form.get('title')
    user_id = get_userid()

    # result = akon.update_tech_links(data)
    data = {
        "user_id": user_id,
        "title": title
    }

    result_json = make_article_link_public(user_id,title)

    data = {
        "user_id": int(user_id),
        "page_size": 100,
        "ltype": None,
        "_id": None
    }

    result = get_data_id(data)

    username = result["username"]

    return redirect(
        f'/la/{username}/articles'
    )

def delete_article_doc(user_id, article_title, date):
    col1 = db["lp_collection"]
    col1.delete_one({'title': article_title})
    # decrement the contribution from here
    query = {'user_id': user_id, 'date': date}
    contrib_doc = col1.find_one(query)
    if contrib_doc:
        col1.update_one(
            query, {'$set': {'contrib': contrib_doc['contrib']-1}})
        return True

@app.route('/la/delete/article', methods=["POST"])
def la_delete_article():

    title = request.form.get('title')
    created_at = request.form.get('created_at')

    user_id = get_userid()

    data = {
        "user_id": user_id,
        "title": title,
        "created_at": created_at
    }

    result_json = delete_article_doc(user_id,title,created_at)

    return redirect(
        '/la/dashboard'
    )

@app.route('/la/mylist/delete/article', methods=["POST"])
def la_my_list_delete_article():

    title = request.form.get('title')
    created_at = request.form.get('created_at')

    user_id = get_userid()

    data = {
        "user_id": user_id,
        "title": title,
        "created_at": created_at
    }

    result_json = delete_article_doc(user_id,title,created_at)
    # result = akon.update_tech_links(data)
    data = {
        "user_id": int(user_id),
        "page_size": 100,
        "ltype": None,
        "_id": None
    }

    result = get_data_id(data)

    username = result["username"]

    return redirect(
        f'/la/{username}/articles'
    )

@app.route('/la/user/get/contributions/<user_id>', methods=["GET"])
def la_get_user_contributions(user_id):

    heatmap_data = get_contribution_of(user_id)
    return jsonify(heatmap_data)

def get_contribution_of(user_id):
    col = db["lp_contribution"]
    data = []
    for docs in col.find({'user_id': int(user_id)}):
        data.append({'date': docs['created_at'], 'contrib': docs['contrib']})
    return data

@app.route('/api/la/add/article', methods=["POST"])

def addArticle():
 
    data = request.get_json()

    user_id = int(data['user_id'])
    link = data['link']
    title = data['title']
    date = data['date']
    try:

        la_tags = data["tags"]

    except:
        la_tags = []

    result_dict = create_article_link_doc(
        user_id, title, link, date, la_tags)
   
    result_dict = {
        "message": "article info added successfully"
    }
    return result_dict

def get_last_la_id():

    col = db["lp_collection"]

    get_last_la_id = col.find().sort(
        [('la_id', -1)]).limit(1)

    try:
        last_la_id = get_last_la_id[0]['la_id']

    except Exception as err:
       
        last_la_id = 0

    return last_la_id

def create_contribution(user_id, date):
    col = db["lp_contribution"]
    query = {'user_id': user_id, 'created_at': date}
    contrib_doc = col.find_one(query)

    if(contrib_doc):
        col.update_one(
            query, {'$set': {'contrib': contrib_doc['contrib']+1}})
    else:
        contrib_data = {'lac_id': get_last_lac_id(
        )+1, 'user_id': user_id, 'created_at': date, 'contrib': 1}
        col.insert_one(contrib_data)

def get_last_lac_id():

    col = db["lp_contribution"]

    get_last_lac_id = col.find().sort([
        ('lac_id', -1)]).limit(1)

    try:
        last_lac_id = get_last_lac_id[0]['lac_id']

    except Exception as err:
       
        last_lac_id = 0

    return last_lac_id

def create_article_link_doc(user_id, title, link, date, la_tags):

    col = db["user_details"]
    col2 = db["lp_collection"]
    col3 = db["lp_tags"]

    cr = date.split("-")

    from datetime import datetime

    UTC_datetime = datetime.utcnow()

    UTC_datetime_timestamp = int(UTC_datetime.strftime("%s"))

    if len(la_tags) == 0:
        query = {'user_id': int(user_id), 'title': title}

        cursor = col2.find_one(query)
        if cursor:
            col2.update_one(
                {"la_id": cursor["la_id"]}, {'$set': {'updated_at': date}})
        else:
            article_data = {
                'la_id': get_last_la_id()+1,
                'user_id': user_id,
                'link': link,
                'title': title,
                'tag_ids': [],
                'created_at': date,
                "updated_at": date,
                'isPrivate': False,
                'created_at_timestamp': UTC_datetime_timestamp
            }

            col2.insert_one(article_data)
            create_contribution(user_id, date)

    for la_tag in la_tags:
        

        query = {'user_id': int(user_id), 'title': title}

        cursor = col2.find_one(query)

        la_tag_search = col3.find_one({
            "la_tag": {
                "$regex": la_tag,
                '$options': 'i'
            }},
        )

        if la_tag_search:
            la_tag_id = la_tag_search["la_tag_id"]

            if cursor:
                tag_id = cursor["tag_ids"]
                if not int(la_tag_id) in cursor["tag_ids"]:
                    tag_id.append(la_tag_search["la_tag_id"])
                    col2.update_one(
                        {"la_id": cursor["la_id"]}, {'$set': {'tag_ids': tag_id}})

            else:
                article_data = {
                    'la_id': get_last_la_id()+1,
                    'user_id': user_id,
                    'link': link,
                    'title': title,
                    'tag_ids': [(la_tag_search["la_tag_id"])],
                    'created_at': date,
                    "updated_at": date,
                    'isPrivate': False,
                    'created_at_timestamp': UTC_datetime_timestamp
                }

                col2.insert_one(article_data)
                create_contribution(user_id, date)

        if not la_tag_search:

            add_la_tag(la_tag, user_id, title, la_tags, link, date)

    return "Success"

def get_last_la_tag_id():

    col = db["lp_tags"]

    last_la_tag_id = col.find().sort([('la_tag_id', -1)]).limit(1)

    try:
        last_la_tag_id = last_la_tag_id[0]['la_tag_id']
    except Exception as err:
     
        last_la_tag_id = 0

    return last_la_tag_id

def add_la_tag(la_tag, user_id, title, la_tags, link, date):
   
    col = db["lp_tags"]
    col2 = db["lp_collection"]

    last_la_tag_id = get_last_la_tag_id()

    current_la_tag_id = last_la_tag_id + 1

    cr = date.split("-")

    from datetime import datetime

    UTC_datetime = datetime.utcnow()

    UTC_datetime_timestamp = int(UTC_datetime.strftime("%s"))

    try:

        la_tags_dict = {
            "la_tag_id": current_la_tag_id,
            "la_tag": la_tag,
            "created_at": datetime.now(),
            "updated_at": datetime.now()
        }
        col.insert_one(la_tags_dict)
        query = {'user_id': int(user_id), 'title': title}

        cursor = col2.find_one(query)

        la_tag_search = col.find_one({
            "la_tag": {
                "$regex": la_tag,
                '$options': 'i'
            }},
        )
        la_tag_id = la_tag_search["la_tag_id"]
        if cursor:
            tag_id = cursor["tag_ids"]

            col2.update_one(
                {"la_id": cursor["la_id"]}, {'$set': {'updated_at': date}})

            if not int(la_tag_id) in cursor["tag_ids"]:
                tag_id.append(la_tag_search["la_tag_id"])

                col2.update_one(
                    {"la_id": cursor["la_id"]}, {'$set': {'tag_ids': tag_id}})

        if cursor is None:
            article_data = {
                'la_id': get_last_la_id()+1,
                'user_id': user_id,
                'link': link,
                'title': title,
                'tag_ids': [(la_tag_search["la_tag_id"])],
                'created_at': date,
                "updated_at": date,
                'isPrivate': False,
                'created_at_timestamp': UTC_datetime_timestamp
            }

            col2.insert_one(article_data)
            create_contribution(user_id, date)

    except pymongo.errors.DuplicateKeyError as duplicate_error:
        return False
    

@app.route('/all/courses', methods=["GET"])
def page_show_all_courses_get():
    s_id = get_sid()
    result_dict = get_visible_courses_ttc()

    return render_template('all_courses.html', result=result_dict)


def get_visible_courses_ttc():
    col = db["course_ttc"]
    # courses = f12_course_ttc.objects(visible=True)
    courses = col.find()

    courses_list = []

    for course in courses:

        course['created_at_fuzzy'] = '1 day ago'

        del course["_id"]

        courses_list.append(course)

    return courses_list

# class course_subscribers_ttc(db.Document):

#     course_subscriber_id    = db.IntField()
#     course_id               = db.IntField()
#     user_id                 = db.IntField()
#     created_at              = db.DateTimeField()
#     subscribed_date         = db.DateTimeField()
#     expiry_date             = db.DateTimeField()
#     updated_at              = db.DateTimeField()

#     def to_json(self):

#         _dict = {
#             "course_subscriber_id"  : self.course_subscriber_id,
#             "course_id"             : self.course_id,
#             "user_id"               : self.user_id,
#             "created_at"            : self.created_at,
#             "subscribed_date"       : self.subscribed_date,
#             "expiry_date"           : self.expiry_date,
#             "updated_at"            : self.updated_at
#         }

#         return _dict
    
# class f12_chapter(db.Document):

#     chap_id          = db.IntField()
#     chap_name        = db.StringField()
#     course_id        = db.IntField()
#     chap_index       = db.IntField()
#     created_at       = db.DateTimeField()
#     updated_at       = db.DateTimeField()

#     def to_json(self):

#         _dict = {
#             "chap_id"        : self.chap_id,
#             "chap_name"      : self.chap_name,
#             "chap_index"     : self.chap_index,   
#             "course_id"      : self.course_id,
#             "created_at"     : self.created_at,
#             "updated_at"     : self.updated_at
#         }

#         return _dict


def get_chapters_of_course(course_id):
    col = db["chapter"]

    courses = col.find({"course_id":int(course_id)})

    courses_list = []

    # tlogger.info(f'courses : {courses}')

    for course in courses:

        # tlogger.info('course : ', course)

        del course["_id"]


        courses_list.append(course)

    return courses_list

def get_details_of_course(course_id, user_id = None):
    col1 = db["course_subscribers_ttc"]
    col = db["topics"]
    details = []

    if(user_id):
        course_subscribers = col1.find({
            "course_id"   : int(course_id), 
            "user_id"     : int(user_id)
        })
    else:
        course_subscribers = col1.find({
            "course_id"   : int(course_id), 
            "user_id"     : None
        })

    from datetime import datetime

    current_date_str = datetime.now()

    try:
        for course_subscriber in course_subscribers:

            # tlogger.info('course : ', course)

            del course_subscriber["_id"]

            expiry_date = course_subscriber['expiry_date']

        if current_date_str < expiry_date:
            validity = True

        else:
            validity = False    # not valid

    except:
        validity = False

    chapters = get_chapters_of_course(course_id)

    for c_chapter in chapters:
        result = col.aggregate([
            {
                "$match":
                {
                    "chap_id": c_chapter["chap_id"]
                }
            },
            {
                "$lookup":
                {
                    "from": "ttc",
                    "localField": "ttc_id",
                    "foreignField": "ttc_id",
                    "as": "TTC_INFO"
                }
            },
            {
                "$unwind": "$TTC_INFO"
            },
            {
                "$lookup":
                {
                    "from": "chapter",
                    "localField": "chap_id",
                    "foreignField": "chap_id",
                    "as": "CHAPTER_INFO"
                }
            },
            {
                "$unwind": "$CHAPTER_INFO"
            }
        ])

        result_list = []
        final_dict = {
            "chapter_topics": []
        }

        for item in result:
            del item["_id"]
            del item["CHAPTER_INFO"]["_id"]
            del item["TTC_INFO"]["_id"]

            final_dict["chapter_topics"].append(item["TTC_INFO"])
            result_list.append(item)

        single_chapter = result_list[0]

        final_dict["chap_id"] = c_chapter["chap_id"]
        final_dict["chap_index"] = single_chapter["CHAPTER_INFO"]["chap_index"]
        final_dict["chap_name"] = single_chapter["CHAPTER_INFO"]["chap_name"]
        final_dict["course_id"] = single_chapter["CHAPTER_INFO"]["course_id"]

        details.append(final_dict)

    return validity, details

# class user_transactions(db.Document):

#     trans_id                 = db.IntField()
#     user_id                  = db.IntField()
#     ref_type_id              = db.IntField()
#     tact_coins               = db.IntField()
#     created_at               = db.DateTimeField()
#     updated_at               = db.DateTimeField()
#     cse_id                   = db.IntField()
#     def to_json(self):

#         _dict = {
#             "trans_id"      : self.trans_id,        
#             "user_id"       : self.user_id,
#             "ref_type_id"   : self.ref_type_id,
#             "tact_coins"    : self.tact_coins,
#             "created_at"    : self.created_at,
#             "updated_at"    : self.updated_at,
#             "cse_id"        : self.cse_id
#         }
        

#         return _dict
    
# class f12_credits(db.Document):
    
#     credits_id              = db.IntField()
#     cse_id                  = db.IntField()
#     user_id                 = db.IntField()
#     tact_credits            = db.IntField()
#     created_at              = db.DateTimeField()
#     updated_at              = db.DateTimeField()

#     def to_json(self):


#         _dict   =   {
#                     "credits_id"    : self.credits_id,
#                     "user_id"       : self.user_id,
#                     "cse_id"        : self.cse_id,
#                     "tact_credits"  : self.tact_credits,
#                     "created_at"    : self.created_at,
#                     "updated_at"    : self.updated_at
#                     }
#         return _dict

def get_users_tact_coins(user_id):
    col = db["user_transactions"]
    col2 = db["credits"]

    user_tact_coins         = col.find({user_id : int(user_id)})
    user_tact_credits       = col2.find({user_id : int(user_id)})

    user_total_tact_coins   = 0
    user_total_credit_coins = 0
    for user_tact_coins in user_tact_coins:

        del user_tact_coins["_id"]

        user_total_tact_coins+=user_tact_coins['tact_coins']

    for user_tact_credit in user_tact_credits:

        del user_tact_credit["_id"]

        user_total_credit_coins+=user_tact_credit['tact_credits']

    return user_total_tact_coins, user_total_credit_coins

def get_credits_info(user_id, course_id):

    col = db["course_ttc"]
    
    category_info       = col.find_one({"course_id": int(course_id)})
    subscription_cost   = category_info['course_credits']

    _, user_total_credits = get_users_tact_coins(
        int(user_id)
    )

    if int(user_total_credits) >= subscription_cost:
        remaining_credits = user_total_credits - subscription_cost
    else:
        remaining_credits = None

    return subscription_cost, user_total_credits, remaining_credits


def get_course_ttc_to_edit(course_id):

    col = db["course_ttc"]
    
    course_ttc = col.find_one({"course_id": int(course_id)})

    name            = course_ttc["name"]
    course_credits  = course_ttc['course_credits']
    visible         = course_ttc["visible"]
    description     = course_ttc["description"]
    subtitle        = course_ttc.get("subtitle", "&nbsp;") 

    try:
        objectives  = course_ttc["objectives"]
    except:
        objectives = []

    course_ttc_info = {
        "name"              : name,
        "course_credits"    : int(course_credits),
        "visible"           : bool(visible),
        "description"       : description,
        "objectives"        : objectives,
        "subtitle"          : subtitle
    }

    return course_ttc_info

@app.route('/course/<course_id>', methods=["GET"])
# @requires_session
def page_show_videos_get_ttc(course_id):

    s_id        = get_sid()
    user_id     = get_userid()

    validity_get, details_get = get_details_of_course(course_id, user_id)
    subscription_cost_get, user_total_credits_get, remaining_credits_get      = get_credits_info(user_id, s_id, course_id)

    result_dict2 = {}
    try:
        result_dict2        = get_course_ttc_to_edit(course_id, s_id)

        objectives          = result_dict2["objectives"]
        user_credits        = user_total_credits_get
        subscription_cost   = subscription_cost_get
        remaining_credits   = remaining_credits_get

        title               = result_dict2["name"]
        description         = result_dict2["description"]
        subtitle            = result_dict2["subtitle"]
        validity            = validity_get
    except Exception as e:

        objectives          = []
        user_credits        = user_total_credits_get
        subscription_cost   = subscription_cost_get
        remaining_credits   = remaining_credits_get

        title               = "Error - title"
        description         = "Error - description"
        subtitle            = "Error - subtitle"
        validity            = validity_get

    return render_template(
        'course_new_ttc.html', 
        result              = details_get, 
        course_id           = course_id, 
        validity            = validity, 
        title               = title, 
        description         = description, 
        subtitle            = subtitle, 
        user_credits        = user_credits, 
        subscription_cost   = subscription_cost, 
        remaining_credits   = remaining_credits, 
        objectives          = objectives
    )


def get_course_ttc(course_id):
    col = db["course_ttc"]
    # course = fs_course_van.objects(course_id = int(course_id))[0]
    
    course = col.find_one({"course_id":int(course_id)})
    
    
    result_dict = {
        "name" : course["name"],
        "course_credits": course["course_credits"],
        "visible"  : course["visible"],
        "description" : course["description"],
        "subtitle"   : course["subtitle"],
        "course_status" : course["course_status"]
     }

    

    return result_dict

def get_video_of_id(ttc_id, course_id):

    col = db["topics"]
    col2 = db["ttc"]

    chapters = get_chapters_of_course(course_id)

    c_course_obj = get_course_ttc(course_id)

    course_name = c_course_obj['name']

    ch_ids              = []
    curr_chap_id        = None
    curr_topic_index    = None
    next_ttc_id         = None
    previous_ttc_id     = None
    all_topics          = []
    course_details      = []

    for c_chapter in chapters:

        ch_ids.append(c_chapter["chap_id"])
        
        

    course_topics = col.find({"chap_id": {"$in": ch_ids}})
    for video in course_topics:
        if video["ttc_id"] == int(ttc_id):
            curr_chap_id        = video["chap_id"]
            curr_topic_index    = video["topic_index"]

        all_topics.append(video)

    bef_temp = list(
        filter(
            lambda ttc: ttc["chap_id"] == curr_chap_id 
            and ttc["topic_index"] == curr_topic_index-1, all_topics
        )
    )

    if len(bef_temp) == 0:
        bef_chapter = list(
            filter(
                lambda ttc: ttc["chap_id"] == curr_chap_id-1, all_topics
            )
        )

        if len(bef_chapter) != 0:
            highest_index = max([x['topic_index'] for x in bef_chapter])
            bef_ttc = list(
                filter(
                    lambda ttc: ttc["chap_id"] == curr_chap_id-1 
                    and ttc["topic_index"] == highest_index, bef_chapter
                )
            )

            previous_ttc_id = bef_ttc[0]["ttc_id"]
    else:
        previous_ttc_id = bef_temp[0]["ttc_id"]

    next_temp = list(
        filter(
            lambda ttc: ttc["chap_id"] == curr_chap_id 
            and ttc["topic_index"] == curr_topic_index+1, all_topics
        )
    )

    if len(next_temp) == 0:
        next_chapter = list(
            filter(
                lambda ttc: ttc["chap_id"] == curr_chap_id+1, all_topics
            )
        )
        if len(next_chapter) != 0:
            lowest_index = min([x['topic_index'] for x in next_chapter])
            next_ttc = list(
                filter(
                lambda ttc: ttc["chap_id"] == curr_chap_id+1 
                and ttc["topic_index"] == lowest_index, next_chapter
            )
        )
            next_ttc_id = next_ttc[0]["ttc_id"]
    else:
        next_ttc_id = next_temp[0]["ttc_id"]

    courses = col2.find_one({"ttc_id":int(ttc_id)})

    courses_list = []

    

    course_dict = {
        "video_title": courses["video_title"],
        "description" : courses["description"],
        "video_link"  : courses["video_link"],
        "video_length" : courses["video_length"]
        }


    courses_list.append(course_dict)



    learners_note = get_learners_note_by_video_id(ttc_id)

    return course_name, courses_list, previous_ttc_id, next_ttc_id, course_details, learners_note

def get_learners_note_by_video_id(ttc_id):

    col = db["ttc_learners_notes"]
    learner_notes = col.find(
        {"ttc_id": ttc_id}
    )

    l_notes = list(
        map(lambda x: {
            'content' : x['content']
        }, learner_notes)
    )

    return l_notes

# class ttc(db.Document):

#     ttc_id          = db.IntField()
#     video_title     = db.StringField()
#     video_author    = db.StringField()
#     video_link      = db.StringField()
#     video_author_id = db.IntField()
#     description     = db.StringField()
#     created_at      = db.DateTimeField()
#     updated_at      = db.DateTimeField()
#     video_length    = db.StringField()
#     is_public       = db.BooleanField()

#     def to_json(self):

#         _dict = {
#             "ttc_id"           : self.ttc_id,
#             "video_title"      : self.video_title,
#             "video_author"     : self.video_author,
#             "video_link"       : self.video_link,
#             "video_author_id"  : self.video_author_id,
#             "description"      : self.description,
#             "created_at"       : self.created_at,
#             "updated_at"       : self.updated_at,
#             "video_length"     : self.video_length,
#             "is_public"        : self.is_public
#         }

#         return _dict
    
@app.route('/course/video/<course_id>/<ttc_id>', methods=["GET"])

def page_show_single_video_ttc_get(course_id, ttc_id):

    s_id    = get_sid()
    user_id = get_userid()
    vimeo   = True

    # result_dict = fpr_business.get_all_course_details(course_id, s_id)
    course_name_get, chapters_get, previous_ttc_id_get, next_ttc_id_get, course_details_get, learners_note_get = get_video_of_id(int(ttc_id),int(course_id))

    # (result_dict) # instead of tips, use learners_note
    # result_dict1 = fpr_business.get_tips(
    #     result_dict["result"]["chapters"][0]["ttc_id"], 
    #     user_id
    # )

    string      = chapters_get[0]["video_link"]
    sub_string  = "youtube"

    if(sub_string in string):
        vimeo = False

    # link = "https://www.youtube.com/embed/il_t1WVLNxk"

    learners_note = []
    if(learners_note_get):
        learners_note = learners_note_get

    return render_template('video_ttc_v2.html', 
        edit            = False, 
        vimeo           = "https://www.youtube.com/embed/il_t1WVLNxk",
        learners_note   = learners_note,
        course_name     = course_name_get,
        side_nav        = course_details_get,
        result          = chapters_get[0],
        prev            = previous_ttc_id_get,
        next            = next_ttc_id_get,
        course_id       = int(course_id)
    )

import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from datetime import datetime, timezone
from datetime import date

from dotenv import load_dotenv

load_dotenv()

SMTP_FROM       = os.getenv('SMTP_FROM')
SMTP_PASSWORD   = os.getenv('SMTP_PASSWORD')
SMTP_PORT       = os.getenv('SMTP_PORT')
SMTP_URL        = os.getenv('SMTP_URL')
SMTP_USERNAME   = os.getenv('SMTP_USERNAME')
ERROR_RECIPIENTS    = os.environ["ERROR_RECIPIENTS"]

def str_to_list(content, delimiter = ','):
    content_list = content.split(delimiter)
    return content_list

def send_email(
    email_subject, 
    email_body,
    to_emails
):

    message = Mail(
        from_email      = SMTP_FROM,
        to_emails       = to_emails,
        subject         = email_subject,
        html_content    = email_body
    )

    try:
        sg_client       = SendGridAPIClient(SMTP_PASSWORD)
        response        = sg_client.send(message)

        print(response.status_code)
        print(response.body)
        # print(response.headers)
    except Exception as e:
        print('Error : ', e)

@app.route("/send/email", methods = ["GET"])
def send_email_post():


    to_emails       = str_to_list(ERROR_RECIPIENTS)
    email_subject   = 'Test Email'
    html_content    = 'Some dummy content'

    send_email(
        email_subject,
        html_content,
        to_emails
    )

    return "sent successfully"
  

if __name__ == '__main__':
    app.run('0.0.0.0', 3000, True)
