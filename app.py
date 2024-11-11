from urllib.parse import urlparse, urljoin
from flask import render_template, redirect, url_for, flash, request, Flask, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_session import Session
import logging
from Database import SecureDB, DatabaseConfig, SecurityConfig
import base64
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    filename='application.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

app = Flask(__name__)

# Enhanced session configuration with security settings
app.config.update(
    SECRET_KEY=secrets.token_hex(32),
    SESSION_TYPE='filesystem',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',  # Enhanced from 'Lax' to 'Strict'
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    # Additional security configurations
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_DURATION=timedelta(days=1),
)

# Initialize Flask-Session
Session(app)

# Setup enhanced security headers
Talisman(app,
         force_https=True,
         strict_transport_security=True,
         session_cookie_secure=True,
         content_security_policy={
             'default-src': "'self'",
             'script-src': "'self'",
             'style-src': "'self'",
             'img-src': "'self' data:",
             'font-src': "'self'",
             'frame-ancestors': "'none'",  # Prevents clickjacking
         },
         feature_policy={
             'geolocation': "'none'",
             'microphone': "'none'",
             'camera': "'none'",
         }
         )

# Setup rate limiting with more restrictive limits
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://"
)

# Initialize database
db = SecureDB()

# Login manager setup with enhanced security
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'
login_manager.login_message = 'Please log in to access this page.'
login_manager.needs_refresh_message = 'Please reauthenticate to protect your account.'


class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.password_hash = user_data['password_hash']
        self.group = user_data['group']
        self.last_login = user_data.get('last_login')
        self.login_attempts = user_data.get('login_attempts', 0)
        self.locked_until = user_data.get('locked_until')
        self._encryption_key = SecurityConfig.ENCRYPTION_KEY
        self.fernet = Fernet(self._encryption_key)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def can_access_full_data(self):
        return self.group == 'H'

    def can_add_records(self):
        return self.group == 'H'

    def verify_data_integrity(self, data, signature):
        """Verify the integrity of a single data item"""
        return db.integrity.verify_record(data, signature)

    def verify_query_completeness(self, records, merkle_root):
        """Verify the completeness of query results"""
        computed_root = db.integrity.compute_merkle_root(records)
        return computed_root == merkle_root

    @staticmethod
    def get_by_username(username):
        conn = None
        try:
            conn = db._get_db_connection(DatabaseConfig.DATABASE)
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT * FROM users 
                WHERE username = %s
            """, (username,))
            user_data = cursor.fetchone()
            return User(user_data) if user_data else None
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()


@login_manager.user_loader
def load_user(user_id):
    conn = None
    try:
        conn = db._get_db_connection(DatabaseConfig.DATABASE)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        return User(user_data) if user_data else None
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


def update_login_attempts(username, success=True):
    conn = None
    try:
        conn = db._get_db_connection(DatabaseConfig.DATABASE)
        cursor = conn.cursor()

        if success:
            # Reset attempts on successful login
            cursor.execute("""
                UPDATE users 
                SET login_attempts = 0, 
                    last_login = NOW(),
                    locked_until = NULL 
                WHERE username = %s
            """, (username,))
        else:
            # Increment attempts and possibly lock account
            cursor.execute("""
                UPDATE users 
                SET login_attempts = login_attempts + 1,
                    locked_until = CASE 
                        WHEN login_attempts >= 4 THEN DATE_ADD(NOW(), INTERVAL 15 MINUTE)
                        ELSE locked_until 
                    END
                WHERE username = %s
            """, (username,))

        conn.commit()
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required')
            return render_template('login.html'), 400

        user = User.get_by_username(username)

        # Check account lockout
        if user and user.locked_until and user.locked_until > datetime.now():
            flash('Account is temporarily locked. Please try again later.')
            return render_template('login.html'), 429

        if user and user.check_password(password):
            update_login_attempts(username, success=True)
            login_user(user)
            session.permanent = True
            session.modified = True

            next_page = request.args.get('next')
            if not next_page or not is_safe_url(next_page):
                next_page = url_for('dashboard')
            return redirect(next_page)

        if user:
            update_login_attempts(username, success=False)

        flash('Invalid username or password')
        return render_template('login.html'), 401

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get data with integrity protection
        result = db.get_user_data(current_user.username, current_user.group)

        # Verify data integrity and completeness
        records = result['records']
        merkle_root = result['merkle_root']

        if not current_user.verify_query_completeness(records, merkle_root):
            flash('Warning: Query results may have been tampered with')
            return render_template('error.html'), 400

        return render_template('dashboard.html',
                               data=records,
                               can_add=current_user.can_add_records(),
                               group=current_user.group)
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        flash('An error occurred while loading the dashboard')
        return redirect(url_for('login'))


@app.route('/add_record', methods=['POST'])
@login_required
def add_record():
    if not current_user.can_add_records():
        flash('Insufficient permissions')
        return redirect(url_for('dashboard')), 403

    try:
        # Sanitize and validate input data
        data = {k: v.strip() for k, v in request.form.items()}
        required_fields = ['first_name', 'last_name', 'age', 'gender', 'condition', 'medication']

        if not all(field in data for field in required_fields):
            flash('All fields are required')
            return redirect(url_for('dashboard')), 400

        # Add record with encryption and integrity protection
        if db.add_record(data, current_user.username):
            flash('Record added successfully')
        else:
            flash('Error adding record')
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"Error adding record: {str(e)}")
        flash('An error occurred while adding the record')
        return redirect(url_for('dashboard')), 500


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc


# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


@app.before_request
def before_request():
    if current_user.is_authenticated:
        if not session.get('last_activity'):
            logout_user()
            return redirect(url_for('login'))

        last_activity = session.get('last_activity')
        if (datetime.now() - datetime.fromtimestamp(last_activity)) > \
                app.config['PERMANENT_SESSION_LIFETIME']:
            logout_user()
            session.clear()
            flash('Your session has expired. Please login again.')
            return redirect(url_for('login'))

        session['last_activity'] = datetime.now().timestamp()


if __name__ == '__main__':
    app.run(ssl_context='adhoc')