from flask import Flask as fl
from flask import render_template
from flask import request,jsonify
import sqlite3
from werkzeug.security import generate_password_hash,check_password_hash
app = fl(__name__)
import datetime
import jwt
from flask import make_response
from flask import Flask, render_template, request, jsonify, redirect, url_for
app.config['SECRET_KEY'] = '5a6eec382935cbfdb6f387493e29902401e44e1e39398cbe067428c9a80f956d'

@app.route('/api/auth/refresh', methods=['POST'])
def api_refresh():
    incoming_refresh = request.cookies.get('refresh_token')
    
    if not incoming_refresh:
        return jsonify({"success": False, "message": "No refresh token provided"}), 401
    try:
        decoded_payload = jwt.decode(incoming_refresh, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded_payload['username']
        
        payload_access = {
            'username': username,
            'exp': datetime.datetime.now() + datetime.timedelta(minutes=5)
        } 
        access_token = jwt.encode(payload_access, app.config['SECRET_KEY'], algorithm='HS256')
        response_data =  jsonify({"Success": True,
                        "message":"Welcome to dashboard"}),200
        response = make_response(response_data)
        response.set_cookie(
            'access_token',
            access_token,
            httponly=True,
            secure=False,        
            max_age=1800)
        return response
    except jwt.ExpiredSignatureError:
        return jsonify({"success": False, "message": "Refresh token expired complete logout"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"success": False, "message": "Token is invalid"}), 401



@app.route('/')
@app.route('/signin')
def signin():
        return render_template('signin.html')
@app.route('/api/dashboard/verify_signin',methods = ['POST'])
def api_signin():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

   
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM accounts WHERE username = ?",(username,))
    result = cursor.fetchone()
    if result == None:
        print("failure1")
        return jsonify({"Success": False,
                        "message":"No matching username password pair found"})
    stored_hashed_password = result[0]


    if check_password_hash(stored_hashed_password, password):
        payload_access = {
            'username': username,
            'exp':datetime.datetime.now() + datetime.timedelta(minutes=5)
        }
        access_token = jwt.encode(payload_access,app.config['SECRET_KEY'],algorithm='HS256')
        
        payload_refresh = {
            'username':username,
            'exp':datetime.datetime.now() + datetime.timedelta(days = 30)
        }
        refresh_token = jwt.encode(payload_refresh,app.config['SECRET_KEY'],algorithm = 'HS256')

        
        print("success")
        response_data =  jsonify({"Success": True,
                        "message":"Welcome to dashboard"}),200
        response = make_response(response_data)
        response.set_cookie(
            'access_token',
            access_token,
            httponly=True,
            secure=False,        
            max_age=1800)
        response.set_cookie(
            'refresh_token',
            refresh_token,
            httponly=True,
            secure=False,        
            max_age=1800)
        
        return response,200
    else:
        print("failure2")
        return jsonify({
            "Success": False,
            "message": "No matching username password pair found"
        })

@app.route('/signup')
def signup():
    return render_template("signup.html")
@app.route('/api/dashboard/verify_signup',methods = ['POST'])
def api_signup():
        
    data = request.get_json(force=True)
    user_password = data.get("password")
    username = data.get("username")
    
    strength_flag = True
    if len(user_password) < 8:
        strength_flag = False
    if user_password.isalpha() or user_password.isdigit():
        strength_flag = False
    
    if not strength_flag:
        return jsonify({
            "success": False,
            "message": "Password is too weak."
        })
        
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts 
            (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)
        ''')
        
        hashed_password = generate_password_hash(user_password, method='pbkdf2:sha256')
        
        cursor.execute(
            "INSERT INTO accounts (username, password) VALUES (?, ?)", 
            (username, hashed_password)
        )
        conn.commit()
        conn.close()
        print(f"User {username} was added to the database")
        payload_access = {
            'username': username,
            'exp':datetime.datetime.now() + datetime.timedelta(minutes=5)
        }
        access_token = jwt.encode(payload_access,app.config['SECRET_KEY'],algorithm='HS256')
        
        payload_refresh = {
            'username':username,
            'exp':datetime.datetime.now() + datetime.timedelta(days = 30)
        }
        refresh_token = jwt.encode(payload_refresh,app.config['SECRET_KEY'],algorithm = 'HS256')
        
        response_data =  jsonify({"Success": True,
                        "message":"Welcome to dashboard"}),200
        response = make_response(response_data)
        response.set_cookie(
            'access_token',
            access_token,
            httponly=True,
            secure=False,        
            max_age=1800)
        response.set_cookie(
            'refresh_token',
            refresh_token,
            httponly=True,
            secure=False,        
            max_age=1800)
        return response,200
        
        
    except sqlite3.IntegrityError:
        print("user was not added")
        return jsonify({
            "success": False,
            "message": "Username is already taken."
        })
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/dashboard/verify', methods=['GET'])
def dashboard_verify():
    access_token = request.cookies.get('access_token')
    if not access_token:
        return jsonify({"success":False,"message":"access token missing"}),401
    try:
        jwt.decode(access_token,app.config['SECRET_KEY'],algorithms = ['HS256'])

        return jsonify({"success":True,"message":"token is authentic"}),200
    except jwt.ExpiredSignatureError:
        print("token expired")
        return jsonify({"success":False,"message":"token expired"}),401
    except jwt.InvalidSignatureError:
        return jsonify({"success":False,"message":"invalid token"}),401
    
    
        

if __name__ == '__main__':
    app.run(port=8000, debug=True)
