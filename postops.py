# mongo.py

import logging
from flask import Flask, Response, jsonify, request
from flask_pymongo import PyMongo
from bson import ObjectId
from bcrypt import hashpw, gensalt, checkpw
from datetime import datetime, timedelta
from functools import wraps
from PostopsJwt import get_token, get_token_payload

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'users_db2'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/users_db'

mongo = PyMongo(app)

log = logging.getLogger('werkzeug')
log.setLevel(logging.INFO)

def add_cors_headers (resp):
  resp.headers['Access-Control-Allow-Origin'] = '*'
  resp.headers['Access-Control-Allow-Headers'] = "Accept, Accept-Encoding, Accept-Language, Authorization, Cache-Control, Connection, Content-Length, Content-Type, Host, Origin, Pragma, Referer, User-Agent"
  resp.headers['Access-Control-Expose-Headers'] = "Accept, Accept-Encoding, Accept-Language, Authorization, Cache-Control, Connection, Content-Length, Content-Type, Host, Origin, Pragma, Referer, User-Agent"
  resp.headers['Access-Control-Allow-Methods'] = "GET, POST, PUT, DELETE, PATCH"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
      payload = None
      if request.method != 'OPTIONS':
        token = request.headers.get('authorization', None)
        payload = get_token_payload(token)
        if payload is None:
          return jsonify({'result' : "err"})
      return f(payload, *args, **kwargs)
    return decorated_function

@app.route('/', methods=['OPTIONS', 'GET'])
def check_server():
  resp = jsonify({'result' : "ok"})
  add_cors_headers(resp)
  return resp

def get_from_stringstore(userid):
#  userid = "5b229b5301914f4899ccf10b"
  useridObj = ObjectId(userid)
  string = mongo.db.stringstore
  ret = []
  for u in string.find({'userid': useridObj}):
    ret.append({'text': u['text'], 'type': u['type']})
  return ret

@app.route('/auth/stringstore', methods=['OPTIONS', 'GET'])
@login_required
def getStrings(payload):
  result = "ok"
  if request.method == 'GET':
    strs = get_from_stringstore(payload['id'])
    result = "ok"
    resp = jsonify(strs)
  else:
    resp = jsonify({'result': 'ok'})
  add_cors_headers(resp)
  return resp

@app.route('/auth/all/stringstore', methods=['OPTIONS', 'PUT'])
@login_required
def put_all_strings(payload):
  if request.method == 'PUT':
    userid = ObjectId(payload['id'])
    string = mongo.db.stringstore
    string.remove({'userid': userid})
    for el in request.json:
      string.insert({'userid': userid, 'text': el['text'], 'type': el['type']})
  resp = jsonify({'result': 'ok'})
  add_cors_headers(resp)
  return resp

@app.route('/auth/stringstore', methods=['POST'])
@login_required
def put_string(payload):
  string = mongo.db.stringstore
  userid = ObjectId(payload['id'])
  for el in request.json:
    string.insert({'userid': userid, 'text': el['text'], 'type': el['type']})
  resp = jsonify({'result': 'ok'})
  add_cors_headers(resp)
  return resp

@app.route('/auth/check', methods=['OPTIONS', 'GET'])
def checkAuth():
  result = "ok"
  if request.method == 'GET':
    token = str(request.headers.get('Authorization'))
    payload = None
    if len(token) > 7:
      payload = get_token_payload(token)
    if payload is None:
      result = "err"
  resp = jsonify({'result' : result})
  add_cors_headers(resp)
  return resp

@app.route('/open/authenticate/<useremail>/<passhash>', methods=['OPTIONS', 'GET'])
def authenticate_user(useremail, passhash):
  user = mongo.db.users
  u = user.find_one({'useremail' : useremail})
  if checkpw(passhash.encode('utf8'), u['password'].encode('utf8')):
    userid = str(u['_id'])
    flags = 1
    expire = int(datetime.now().timestamp())
    token = get_token(userid, expire, flags)
    resp = jsonify({'result' : "ok"})
    resp.headers['Authorization'] = "Bearer " + token
  else:
    resp = jsonify({'result' : "err"})
  add_cors_headers(resp)
  return resp

@app.route('/open/users', methods=['POST', 'OPTIONS'])
def add_user():
  if request.method == 'POST' :
    user = mongo.db.users
    useremail = request.json['useremail']
    passhash = request.json['password']
    u = user.find_one({'useremail' : useremail})
    if not u:
      passbcrypt = hashpw(passhash.encode('utf8'), gensalt())
      user_id = user.insert({'useremail': useremail, 'password': passbcrypt.decode('utf8')})

  resp = jsonify({'result' : "ok"})
  add_cors_headers(resp)
  return resp

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=6026)
