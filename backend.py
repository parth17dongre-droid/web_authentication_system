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



@app.route('/api/dashboard/verify',methods = ['GET'])
def verify_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"success":False,"message":"token is missing"})
    try:
        token = auth_header.split(" ")[1]
        data = jwt.decode(token,app.config['SECRET_KEY'],algorithms = ['HS256'])
        return jsonify({"success":True,"message":"Token verified","username": data['username']}),200
    except jwt.ExpiredSignatureError:
        return jsonify({"success":False,"message":"token expired"}),401
    except jwt.InvalidSignatureError:
        return jsonify({"success":False,"message":"Token is invalid"}),401
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
        payload = {
            'username': username,
            'exp':datetime.datetime.now() + datetime.timedelta(minutes=30)
        }
        token = jwt.encode(payload,app.config['SECRET_KEY'],algorithm='HS256')
        
        
        print("success")

        return jsonify({"Success": True,
                        "token":token,
                        "message":"Welcome to dashboard"}),200
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
        payload = {
            'username': username,
            'exp':datetime.datetime.now() + datetime.timedelta(minutes=30)
        }
        token = jwt.encode(payload,app.config['SECRET_KEY'],algorithm='HS256')
        
        return jsonify({"Success": True,
                        "token":token,
                        "message":"Welcome to dashboard"}),200
        
        
    except sqlite3.IntegrityError:
        print("user was not added")
        return jsonify({
            "success": False,
            "message": "Username is already taken."
        })
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

    
        

if __name__== '__main__':
    app.run(port = 8000,debug = True)