

# Import necessary modules

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os
import logging

# DB import
from flask_pymongo import PyMongo,pymongo

# Local Import
from error_code import ErrorCode
import response_utils
from controllers import *
# from business.scheduler_handler import 
from flask_apscheduler import APScheduler
# scheduler methods import
import time
from flask import Blueprint

api = Blueprint('featurepreneur_api_bp', __name__)

app = Flask(__name__)

FPR_BACKEND_PORT = 3000




# this will set the UTC time instead of local
# logging.Formatter.converter = time.gmtime

app.register_blueprint(api)

# app configs
app.config["MONGO_URI"] = "mongodb+srv://prakash-1211:prakash@cluster0.enw9p.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"



app.config['MONGODB_SETTINGS'] = {
    'db': 'teamit',
    'host': app.config["MONGO_URI"]
}

mongo = PyMongo(app)
bcrypt = Bcrypt()
CORS(app)

# APscheduler
# if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":

scheduler = APScheduler()
scheduler.init_app(app)
    
##


app.secret_key = 'fixutureTa$eDilda$S' 



if __name__ == "__main__":
    
    app.config['city'] = 'Toronto'

    app.run('0.0.0.0', 5000, True)