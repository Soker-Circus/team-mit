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
            recent_links = recent_links['links']
        if top_contributors["result"]:
            top_contributors = top_contributors["result"]['contributors']
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

            doc["updated_at"] = datetime(int(d[0]), int(
                d[1]), int(d[2])).strftime("%A, %d %B %Y")

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

        return render_template('learning-analytics-contributors.html', data=result['contributors'], logged_in=logged_in, username=results["username"])
    return render_template('learning-analytics-contributors.html', data=result['contributors'], logged_in=logged_in)

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
    all_tags = all_tags["user_tag_list"]
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

    result_json = make_article_link_public(data)

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

