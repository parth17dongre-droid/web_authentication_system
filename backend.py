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
import uuid
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os


@app.route('/')
@app.route('/signin')
def signin():
        return render_template('signin.html')

@app.route('/signup')
def signup():
    return render_template("signup.html")

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route("/forgot_password")
def forgot_password_view():
    return render_template("forgot_password.html")

@app.route('/api/dashboard/verify_signup',methods = ['POST'])
def api_signup():
        
    data = request.get_json(force=True)
    user_password = data.get("password")
    username = data.get("username")
    email = data.get("user_email")
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
            (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT,user_email TEXT)
        ''')
        
        hashed_password = generate_password_hash(user_password, method='pbkdf2:sha256')
        
        cursor.execute("INSERT INTO accounts (username, password, user_email) VALUES (?, ?, ?)", (username, hashed_password, email))
        conn.commit()
        conn.close()
        print(f"User {username} with email {email} was added to the database")
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

        
        refresh_jti = str(uuid.uuid4())
        refresh_expiry = datetime.datetime.now() + datetime.timedelta(days=30)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO user_sessions (username, jti, expires_at) VALUES (?, ?, ?)",
            (username, refresh_jti, refresh_expiry)
    )
        conn.commit()
        conn.close()
        payload_refresh = {
            'username':username,
            'jti':refresh_jti,
            'exp':refresh_expiry
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

@app.route('/api/auth/refresh', methods=['POST'])
def api_refresh():
    incoming_refresh = request.cookies.get('refresh_token')
    
    if not incoming_refresh:
        return jsonify({"success": False, "message": "No refresh token provided"}), 401
    try:
        decoded_payload = jwt.decode(incoming_refresh, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded_payload['username']
        token_jti = decoded_payload.get('jti')
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM user_sessions WHERE jti = ?", (token_jti,))
        session_record = cursor.fetchone()
        conn.close()
        if session_record is None:
            return jsonify({"success":False,"message":"session record missing"}),401
        
        
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

@app.route('/api/dashboard/forgot_password',methods = ['POST'])
def forgot_password():
    data = request.get_json()
    print(data)
    username = data.get('username')
    input_email = data.get('email')

    otp = "".join(secrets.choice("0123456789") for _ in range(4))
    otp_to_store = otp
    expiry_time = (datetime.datetime.now() + datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS temporary_otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        otp_hash TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')
    
   

    cursor.execute("SELECT user_email FROM accounts WHERE user_email = ?", (input_email,))
    result = cursor.fetchone()
    if result is None:

        conn.close()
        print(f"⚠️ Security Alert: Email '{input_email}' does not exist in the database.")
        return jsonify({"success": False, "message": "Email not found"}), 404
    email = result[0]
    print(email)
    print(f"DEBUG EXPLICIT TARGET: ->|{email}|<-")
    
    print(input_email)
    smtp_server = "smtp.gmail.com"
    smtp_port = 465
    sender_email = "parth17dongre@gmail.com"
    sender_password = "yznnugllipnwunhs"


    message = MIMEMultipart()
    message['From'] = f"SIT Auth System <{sender_email}>" 
    message['To'] = email
    message['Subject'] = "Your One-Time Security Verification Code"
    
    body = f"Hello {username},\n\nYour temporary verification code is: {otp}\n\nThis code will expire in exactly 5 minutes."
    message.attach(MIMEText(body, 'plain'))
    cursor.execute('''
        UPDATE accounts 
        SET otp = ? 
        WHERE user_email = ?
    ''', (otp, input_email))
    conn.commit()
    print("Entered OTP into database with expiry:", expiry_time)
    conn.commit()
    conn.close()

    try:
        print(f"Attempting to send OTP {otp} to {email} via SMTP...")
        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        
        server.login(sender_email, sender_password)
        server.sendmail(sender_email,email, message.as_string())
        server.quit()
        
        print(f"Success! Sent OTP {otp} to {email}")
        return jsonify({"success": True, "message": "OTP sent successfully to registered email."}), 200
    
        
    except Exception as e:
        print(f"SMTP Email dispatch failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": "Failed to dispatch verification email."}), 500

@app.route('/api/dashboard/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    otp = data.get('otp')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT  otp FROM accounts WHERE otp = ?", (otp,))
    result = cursor.fetchone()
    input_otp = result[0]
    if result is None:
        conn.close()
        return jsonify({"success": False, "message": "Invalid OTP"}), 400
    if input_otp == otp:
        conn.close()
        return jsonify({"success": True, "message": "OTP verified successfully."}), 200

@app.route('/api/dashboard/logout', methods=['POST'])
def logout():
    incoming_refresh = request.cookies.get('refresh_token')
    if incoming_refresh:
        try:
            decoded_payload = jwt.decode(incoming_refresh, app.config['SECRET_KEY'], algorithms=['HS256'], options={"verify_signature": True})
            token_jti = decoded_payload.get('jti')
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_sessions WHERE jti = ?", (token_jti,))
            conn.commit()
            conn.close()
        except jwt.InvalidTokenError:
            pass
    response = make_response(jsonify({"success": True, "message": "Logged out safely"}))
    response.set_cookie('access_token', '', expires=0, httponly=True)
    response.set_cookie('refresh_token', '', expires=0, httponly=True)
    return response, 200
@app.route('/api/dashboard/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    username = data.get('username')
    new_password = data.get('new_password')
    print(f"Received password reset request for user: {username}")
    print(f"New password (before hashing): {new_password}")
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE accounts SET password = ? WHERE username = ?", (hashed_password, username))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Password reset successful."}), 200

if __name__ == '__main__':
    app.run(port=8000, debug=True)