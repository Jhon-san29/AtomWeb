import os
import re
import sqlite3
import hashlib
import json
import logging
from datetime import datetime

# Add these Flask-related imports
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'atomByCarterJ')

# Security configurations
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Security features
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# API constants
SEND_OTP_URL = "https://store.atom.com.mm/mytmapi/v1/my/local-auth/send-otp"
VERIFY_OTP_URL = "https://store.atom.com.mm/mytmapi/v1/my/local-auth/verify-otp"
USER_ID = os.getenv('ATOM_USER_ID', '35474357')
VERSION = os.getenv('ATOM_VERSION', '4.12.0')

# Common headers for API requests
COMMON_HEADERS = {
    "User-Agent": "MyTM/4.12.0/Android/27",
    "X-Server-Select": "production",
    "Device-Name": "Xiaomi Redmi 5 Plus",
    "Content-Type": "application/json; charset=UTF-8"
}

# Database setup
def init_db():
    conn = sqlite3.connect('otp_auth.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 phone_number TEXT UNIQUE NOT NULL,
                 status TEXT DEFAULT 'new',
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create tokens table
    c.execute('''CREATE TABLE IF NOT EXISTS tokens (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER NOT NULL,
                 access_token TEXT,
                 refresh_token TEXT,
                 access_token_expire_at INTEGER,
                 refresh_token_expire_at INTEGER,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    # Create otp_requests table
    c.execute('''CREATE TABLE IF NOT EXISTS otp_requests (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER NOT NULL,
                 otp_code TEXT,
                 status TEXT,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    conn.commit()
    conn.close()

def migrate_db():
    conn = sqlite3.connect('otp_auth.db')
    c = conn.cursor()
    
    try:
        # Check if admins table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admins'")
        admin_table_exists = c.fetchone() is not None
        
        if not admin_table_exists:
            logger.info("Creating admins table...")
            c.execute('''CREATE TABLE admins (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         username TEXT UNIQUE NOT NULL,
                         password_hash TEXT NOT NULL,
                         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # Future migrations can be added here
        # Example:
        # c.execute("SELECT * FROM pragma_table_info('admins') WHERE name='new_column'")
        # if not c.fetchone():
        #     c.execute("ALTER TABLE admins ADD COLUMN new_column TEXT")
    
    except Exception as e:
        logger.error(f"Database migration failed: {str(e)}")
    finally:
        conn.commit()
        conn.close()

# Initialize and migrate database
init_db()
migrate_db()

# Helper function to get database connection
def get_db_connection():
    conn = sqlite3.connect('otp_auth.db')
    conn.row_factory = sqlite3.Row
    return conn

# Helper function to validate phone number
def is_valid_phone_number(number):
    return re.match(r'^\d{10}$', number) is not None

# Helper function to encrypt sensitive data
def simple_encrypt(data):
    if not data:
        return data
    return f"ENCRYPTED_{data[::-1]}"

# Helper function to decrypt data
def simple_decrypt(data):
    if not data or not data.startswith("ENCRYPTED_"):
        return data
    return data.replace("ENCRYPTED_", "")[::-1]

# Password hashing functions
def hash_password(password):
    salt = os.urandom(32)  # 32-byte salt
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        100000  # Number of iterations
    )
    return salt + key

def verify_password(stored_hash, password):
    salt = stored_hash[:32]  # First 32 bytes are salt
    key = stored_hash[32:]   # Remaining bytes are key
    new_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return new_key == key

# Check if admin exists
def admin_exists():
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM admins').fetchone()
    conn.close()
    return admin is not None

@app.context_processor
def utility_processor():
    return dict(admin_exists=admin_exists)

# Admin authentication middleware
def admin_required(f):
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/', endpoint='home')
@admin_required
def home():
    return render_template('index.html')

@app.route('/admin/login', methods=['GET', 'POST'], endpoint='admin_login')
def admin_login():
    # If admin is already logged in, redirect to home
    if session.get('admin_logged_in'):
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('admin_login.html')
        
        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if not admin:
            flash('Invalid username or password', 'error')
            return render_template('admin_login.html')
        
        if verify_password(admin['password_hash'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')
            return render_template('admin_login.html')
    
    return render_template('admin_login.html')

@app.route('/admin/setup', methods=['GET', 'POST'], endpoint='admin_setup')
def admin_setup():
    # Redirect if admin already exists
    if admin_exists():
        flash('Admin account already exists', 'warning')
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('admin_setup.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('admin_setup.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return render_template('admin_setup.html')
        
        password_hash = hash_password(password)
        
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO admins (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
            conn.commit()
            flash('Admin account created successfully! Please log in', 'success')
            return redirect(url_for('admin_login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
            return render_template('admin_setup.html')
        finally:
            conn.close()
    
    return render_template('admin_setup.html')

@app.route('/admin/logout', endpoint='admin_logout')
@admin_required
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('admin_login'))

# Send OTP route
@limiter.limit("5 per minute")
@app.route('/send_otp', methods=['POST'], endpoint='send_otp')
@admin_required
def send_otp():
    phone_number = request.form.get('phone_number', '').strip()
    
    if not is_valid_phone_number(phone_number):
        logger.warning(f"Invalid phone number: {phone_number}")
        flash('Invalid phone number. Please enter a 10-digit number.', 'error')
        return redirect(url_for('home'))
    
    full_number = '95' + phone_number
    zero_prefix_number = '0' + phone_number
    
    conn = None
    try:
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE phone_number = ?', (phone_number,)).fetchone()
        
        if not user:
            conn.execute('INSERT INTO users (phone_number) VALUES (?)', (phone_number,))
            conn.commit()
            user = conn.execute('SELECT * FROM users WHERE phone_number = ?', (phone_number,)).fetchone()
        
        # Prepare API request
        headers = {
            **COMMON_HEADERS,
            "X-Attempted-Msisdn": zero_prefix_number
        }
        
        params = {
            "msisdn": full_number,
            "userid": USER_ID,
            "v": VERSION
        }
        
        payload = {"msisdn": full_number}
        
        logger.info(f"Sending OTP to {full_number} (User ID: {user['id']})")
        
        response = requests.post(
            SEND_OTP_URL,
            params=params,
            json=payload,
            headers=headers,
            timeout=15
        )
        
        # Handle API response
        if response.status_code != 200:
            logger.error(f"API Error: Status {response.status_code} - {response.text}")
            flash('Failed to send OTP. Please try again later.', 'error')
            return redirect(url_for('home'))
        
        response_data = response.json()
        logger.debug(f"API Response: {response_data}")
        
        if response_data.get('status') == "success":
            attribute = response_data.get('data', {}).get('attribute', {})
            msisdn = attribute.get('msisdn', '')
            otp_code = attribute.get('code', '')
            
            if otp_code:
                # Log OTP request
                conn.execute(
                    'INSERT INTO otp_requests (user_id, otp_code, status) VALUES (?, ?, ?)',
                    (user['id'], otp_code, 'sent')
                )
                conn.execute(
                    'UPDATE users SET status = ? WHERE id = ?', 
                    ('otp_sent', user['id'])
                )
                conn.commit()
                
                logger.info(f"OTP sent successfully to {full_number}")
                session['phone_number'] = phone_number
                return redirect(url_for('verify_otp_page'))
        
        # Handle API errors
        error_msg = response_data.get('message', 'Unknown error')
        logger.error(f"OTP Send Failed: {error_msg}")
        
        conn.execute(
            'INSERT INTO otp_requests (user_id, status) VALUES (?, ?)',
            (user['id'], 'failed')
        )
        conn.execute(
            'UPDATE users SET status = ? WHERE id = ?', 
            ('otp_failed', user['id'])
        )
        conn.commit()
        
        flash(f'Failed to send OTP: {error_msg}', 'error')
        return redirect(url_for('home'))
    
    except requests.exceptions.RequestException as e:
        logger.exception(f"Network error: {str(e)}")
        flash('Network error. Please check your connection and try again.', 'error')
        return redirect(url_for('home'))
    
    except Exception as e:
        logger.exception(f"Unexpected error: {str(e)}")
        flash('An unexpected error occurred. Please try again later.', 'error')
        return redirect(url_for('home'))
    
    finally:
        if conn:
            conn.close()

# Verify OTP page
@app.route('/verify', endpoint='verify_otp_page')
@admin_required
def verify_otp_page():
    phone_number = session.get('phone_number', '')
    if not phone_number:
        flash('Please request an OTP first.', 'error')
        return redirect(url_for('home'))
    return render_template('verify.html', phone_number=phone_number)

# Verify OTP submission
@app.route('/verify_otp', methods=['POST'], endpoint='verify_otp')
@admin_required
def verify_otp():
    phone_number = session.get('phone_number', '')
    if not phone_number:
        flash('Session expired. Please request OTP again.', 'error')
        return redirect(url_for('home'))
    
    user_otp = request.form.get('otp_code', '').strip()
    
    if not user_otp:
        flash('Please enter the OTP code.', 'error')
        return render_template('verify.html', phone_number=phone_number)
    
    full_number = '95' + phone_number
    
    conn = None
    try:
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE phone_number = ?', (phone_number,)).fetchone()
        
        if not user:
            flash('No OTP request found for this number. Please request OTP first.', 'error')
            return redirect(url_for('home'))
        
        # Get the latest OTP token from database
        otp_request = conn.execute(
            'SELECT otp_code FROM otp_requests WHERE user_id = ? AND status = ? ORDER BY created_at DESC LIMIT 1',
            (user['id'], 'sent')
        ).fetchone()
        
        if not otp_request or not otp_request['otp_code']:
            flash('OTP session expired. Please request a new OTP.', 'error')
            return render_template('verify.html', phone_number=phone_number)
        
        server_code = otp_request['otp_code']
        
        # Prepare API request
        params = {
            "msisdn": full_number,
            "userid": USER_ID,
            "v": VERSION
        }
        
        payload = {
            "msisdn": full_number,
            "code": server_code,
            "otp": user_otp
        }
        
        logger.info(f"Verifying OTP for {full_number} | Server code: {server_code} | User OTP: {user_otp}")
        
        response = requests.post(
            VERIFY_OTP_URL,
            params=params,
            json=payload,
            headers=COMMON_HEADERS,
            timeout=15
        )
        
        # Handle API response
        if response.status_code != 200:
            logger.error(f"API Error: Status {response.status_code} - {response.text}")
            flash('Failed to verify OTP. Please try again later.', 'error')
            return render_template('verify.html', phone_number=phone_number)
        
        response_data = response.json()
        logger.debug(f"API Response: {response_data}")
        
        if response_data.get('status') == "success":
            attribute = response_data.get('data', {}).get('attribute', {})
            access_token = attribute.get('token', '')
            refresh_token = attribute.get('refresh_token', '')
            access_token_expire_at = attribute.get('access_token_expire_at', 0)
            refresh_token_expire_at = attribute.get('refresh_token_expire_at', 0)
            
            if access_token and refresh_token:
                # Encrypt tokens before storage
                encrypted_access = simple_encrypt(access_token)
                encrypted_refresh = simple_encrypt(refresh_token)
                
                # Store tokens
                conn.execute(
                    'INSERT INTO tokens (user_id, access_token, refresh_token, access_token_expire_at, refresh_token_expire_at) VALUES (?, ?, ?, ?, ?)',
                    (user['id'], encrypted_access, encrypted_refresh, access_token_expire_at, refresh_token_expire_at)
                )
                
                # Update user status
                conn.execute(
                    'UPDATE users SET status = ? WHERE id = ?', 
                    ('verified', user['id'])
                )
                
                # Update OTP request status
                conn.execute(
                    'UPDATE otp_requests SET status = ? WHERE user_id = ? AND status = ?',
                    ('verified', user['id'], 'sent')
                )
                
                conn.commit()
                
                logger.info(f"OTP verified for {full_number}")
                session.pop('phone_number', None)
                return render_template('success.html', 
                                      phone_number=phone_number,
                                      access_token=access_token,
                                      refresh_token=refresh_token,
                                      access_expire=datetime.fromtimestamp(access_token_expire_at).strftime('%Y-%m-%d %H:%M:%S'),
                                      refresh_expire=datetime.fromtimestamp(refresh_token_expire_at).strftime('%Y-%m-%d %H:%M:%S'))
        
        # Handle verification failures
        error_msg = response_data.get('message', 'Verification failed')
        logger.error(f"OTP Verification Failed: {error_msg}")
        
        conn.execute(
            'INSERT INTO otp_requests (user_id, status) VALUES (?, ?)',
            (user['id'], 'verification_failed')
        )
        conn.execute(
            'UPDATE users SET status = ? WHERE id = ?', 
            ('verification_failed', user['id'])
        )
        conn.commit()
        
        flash(f'OTP verification failed: {error_msg}', 'error')
        return render_template('verify.html', phone_number=phone_number)
    
    except requests.exceptions.RequestException as e:
        logger.exception(f"Network error: {str(e)}")
        flash('Network error during verification. Please try again.', 'error')
        return render_template('verify.html', phone_number=phone_number)
    
    except Exception as e:
        logger.exception(f"Unexpected error: {str(e)}")
        flash('An unexpected error occurred during verification.', 'error')
        return render_template('verify.html', phone_number=phone_number)
    
    finally:
        if conn:
            conn.close()

# User management page
@app.route('/users', endpoint='user_list')
@admin_required
def user_list():
    conn = get_db_connection()
    users = conn.execute('''
        SELECT u.id, u.phone_number, u.status, u.created_at, 
               t.access_token, t.refresh_token, t.access_token_expire_at, t.refresh_token_expire_at
        FROM users u
        LEFT JOIN (
            SELECT user_id, access_token, refresh_token, access_token_expire_at, refresh_token_expire_at, 
                   MAX(created_at) as latest
            FROM tokens
            GROUP BY user_id
        ) t ON u.id = t.user_id
        ORDER BY u.created_at DESC
    ''').fetchall()
    
    # Prepare data for display
    display_users = []
    for user in users:
        decrypted_access = simple_decrypt(user['access_token']) if user['access_token'] else None
        decrypted_refresh = simple_decrypt(user['refresh_token']) if user['refresh_token'] else None
        
        display_users.append({
            'id': user['id'],
            'phone_number': user['phone_number'],
            'status': user['status'],
            'created_at': user['created_at'],
            'access_token': decrypted_access[:10] + '...' if decrypted_access else None,
            'refresh_token': decrypted_refresh[:10] + '...' if decrypted_refresh else None,
            'access_expire': datetime.fromtimestamp(user['access_token_expire_at']).strftime('%Y-%m-%d %H:%M:%S') if user['access_token_expire_at'] else None,
            'refresh_expire': datetime.fromtimestamp(user['refresh_token_expire_at']).strftime('%Y-%m-%d %H:%M:%S') if user['refresh_token_expire_at'] else None
        })
    
    conn.close()
    return render_template('users.html', users=display_users)

# Health check endpoint
@app.route('/health', endpoint='health_check')
def health_check():
    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)