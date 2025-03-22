"""
JWT: JSON Web Tokens

This python code implements an authentication wrapper using JWT

Questions: 
1. Identify potential security issues in JWT and database interactions.
2. Describe all attack scenarios in as much detail as possible using the security issues reported.
3. Provide fixes for all the identified issues.

How: 
Research on common SQL and JWT issues and bypasses.
"""

from flask import Flask, request, make_response, jsonify
import jwt
import pickle
import sqlite3
import logging
from dotenv import load_dotenv
from utils.db_utils import DatabaseUtils
from utils.file_storage import FileStorage
import bcrypt
from functools import wraps
import os
from datetime import datetime, timedelta

app = Flask(__name__)
load_dotenv()
SECRET_KEY = os.getenv("JWT_SECRET_KEY") 

logging.basicConfig(level=logging.INFO)
db = DatabaseUtils()
fs = FileStorage()


def generate_password_hash(password: str) -> str:
    """Generates a secure hashed password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def check_password_hash(password: str, hashed_password: str) -> bool:
    """Verifies a password against a stored bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def _init_app():
    db.update_data("DROP TABLE IF EXISTS users;")
    db.update_data('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            password TEXT NOT NULL,
                            privilege INTEGER
                        );''')
     # Store hashed passwords instead of plaintext
    hashed_password1 = generate_password_hash('password1')
    hashed_password2 = generate_password_hash('adminpassword1')
    
    db.update_data("INSERT INTO users (username, password, privilege) VALUES (?, ?, ?)", 
                  ('user1', hashed_password1, 0))
    db.update_data("INSERT INTO users (username, password, privilege) VALUES (?, ?, ?)", 
                  ('admin1', hashed_password2, 1))     


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
            
        try:
            # Decode JWT token
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            # Get the current user from the database
            user = db.fetch_data("SELECT * FROM users WHERE username = ?", (payload['username'],))
            
            if not user:
                return jsonify({'message': 'Invalid token'}), 401
                
            # Add user data to the request context
            request.current_user = {
                'username': user[0][1],
                'privilege': user[0][3]
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
            
        return f(*args, **kwargs)
    return decorated



@app.route("/login", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    username = request.json.get("username")
    password = request.json.get("password")
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    
    user = db.fetch_data("SELECT * FROM users WHERE username = ?", (username,))
   
    if not user or not check_password_hash(password, user[0][2]):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Create token with expiration
    expiration = datetime.utcnow() + timedelta(hours=1)
    token = jwt.encode({
        'username': username,
        'privilege': user[0][3],
        'exp': expiration
    }, SECRET_KEY, algorithm="HS256")
    
    res = make_response(jsonify({"message": "Login successful"}))
    
    # Set secure cookie
    res.set_cookie(
        "token", 
        value=token, 
        httponly=True,          # Prevents JavaScript access
        secure=True,            # Only transmitted over HTTPS
        samesite='Strict',      # CSRF protection
        max_age=3600            # 1 hour expiration
    )
    
    return res



@app.route("/logout", methods=["POST"])
def logout():
    res = make_response(jsonify({"message": "Logout successful"}))
    res.set_cookie(
        "token", 
        "", 
        expires=0, 
        secure=True,      # Ensures cookie is only sent over HTTPS
        httponly=True,    # Prevents JavaScript access to cookie
        samesite='Strict' # Prevents CSRF attacks
    )
    return res


@app.route("/file", methods=["GET", "POST", "DELETE"])
@token_required
def store_file():
    """
    Only admins can upload/delete files.
    All users can read files.
    """
    current_user = request.current_user
    
    if request.method == 'GET':
        filename = request.args.get('filename')
        if not filename:
            return jsonify({"error": "Filename is required"}), 400
            
        content = fs.get(filename)
        if content is None:
            return jsonify({"error": "File not found"}), 404
            
        response = make_response(content)
        response.headers.set('Content-Type', 'application/octet-stream')
        response.headers.set('Content-Disposition', f'attachment; filename={os.path.basename(filename)}')
        return response
        
    elif request.method == 'POST':
        if current_user['privilege'] != 1:
            return jsonify({"error": "Admin access required"}), 403
            
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
            
        uploaded_file = request.files['file']
        if uploaded_file.filename == '':
            return jsonify({"error": "No selected file"}), 400
            
        try:
            fs.store(uploaded_file.filename, uploaded_file.read())
            return jsonify({"message": f"File {uploaded_file.filename} uploaded successfully"})
        except ValueError as e:
            logging.error(f"File upload error: {e}")  # Log the actual error for debugging
            return jsonify({"error": "Failed to upload file due to an internal error"}), 400
            
    elif request.method == 'DELETE':
        if current_user['privilege'] != 1:
            return jsonify({"error": "Admin access required"}), 403
            
        filename = request.args.get('filename')
        if not filename:
            return jsonify({"error": "Filename is required"}), 400
            
        if fs.delete(filename):
            return jsonify({"message": f"File {filename} deleted successfully"})
        else:
            return jsonify({"error": "File deletion failed"}), 500
            
    else:
        return jsonify({"error": "Method not implemented"}), 405

if __name__ == "__main__":
    _init_app()
    app.run(host='0.0.0.0', debug=False, port=9090)