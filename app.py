import sys

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from Database import SecureDB, DataConfidentiality, IntegrityProtection, AccessControl
import logging
import os
from datetime import datetime, timedelta
import json

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s [%(filename)s:%(lineno)d]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d]: %(message)s')
console_handler.setFormatter(formatter)
logging.getLogger().addHandler(console_handler)

app = Flask(__name__)
# Use a secure random key in production
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize database
db = SecureDB()


# Security middlewares and decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logging.warning(f"Unauthorized access attempt to {request.path}")
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_group' not in session or session['user_group'] != 'H':
            logging.warning(f"Non-admin access attempt to {request.path} by user {session.get('username')}")
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated_function



@app.before_request
def before_request():
    """Security checks before each request"""
    if 'user_id' in session:
        try:
            # Check if session is still valid
            conn = db._get_db_connection(db.config.DATABASE)
            cursor = conn.cursor(dictionary=True)

            # Check user existence and account status
            cursor.execute("""
                SELECT id, locked_until, login_attempts 
                FROM users 
                WHERE id = %s
            """, (session['user_id'],))

            user = cursor.fetchone()
            if not user:
                session.clear()
                flash('Session expired. Please login again.', 'error')
                return redirect(url_for('login'))

            # Check if account is locked
            if user['locked_until'] and user['locked_until'] > datetime.now():
                session.clear()
                flash('Your account is temporarily locked. Please try again later.', 'error')
                return redirect(url_for('login'))

        except Exception as e:
            logging.error(f"Session validation error: {str(e)}")
            session.clear()
            flash('An error occurred. Please login again.', 'error')
            return redirect(url_for('login'))
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()


# Basic routes
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Clear any existing session
    session.clear()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            # Basic validation
            if not username or not password:
                flash('Please provide both username and password.', 'error')
                return render_template('login.html')

            # Simple authentication for testing
            if username == "admin" and password == "Admin@123456":
                session['user_id'] = 1
                session['username'] = username
                session['user_group'] = 'H'
                session.permanent = True
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            elif username == "regular_user" and password == "Regular@123456":
                session['user_id'] = 2
                session['username'] = username
                session['user_group'] = 'R'
                session.permanent = True
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))

            flash('Invalid username or password.', 'error')
            return render_template('login.html')

        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            flash('An error occurred during login.', 'error')
            return render_template('login.html')

    # GET request - show login form
    return render_template('login.html')


@app.route('/logout')
def logout():
    logging.info(f"User {session.get('username')} logged out")
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    try:
        logging.info(f"Loading dashboard for user: {session.get('username')}")
        return render_template(
            'dashboard.html',
            username=session.get('username'),
            user_group=session.get('user_group')
        )
    except Exception as e:
        logging.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('login'))


@app.route('/dashboard/data')
@login_required
def dashboard_data():
    try:
        username = session.get('username')
        user_group = session.get('user_group')

        # Get dashboard manager instance
        dashboard_manager = db.get_dashboard_manager()

        # Get search parameters
        search_term = request.args.get('search')
        filters = {
            'gender': request.args.get('gender'),
            'age_min': request.args.get('age_min'),
            'age_max': request.args.get('age_max')
        }

        if search_term or any(filters.values()):
            result = dashboard_manager.search_records(user_group, search_term, filters)
        else:
            result = dashboard_manager.get_dashboard_data(username, user_group)

        if not result['success']:
            raise Exception(result.get('error', 'Unknown error occurred'))

        return jsonify({
            'success': True,
            'records': result['records'],
            'count': result['count'],
            'user_group': user_group
        })

    except Exception as e:
        logging.error(f"Dashboard data error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e),
            'records': [],
            'count': 0
        }), 500


@app.route('/add-record', methods=['GET', 'POST'])
@login_required
@admin_required
def add_record():
    if request.method == 'POST':
        try:
            record_data = {
                'first_name': request.form.get('first_name'),
                'last_name': request.form.get('last_name'),
                'age': request.form.get('age'),
                'gender': request.form.get('gender'),
                'weight': float(request.form.get('weight', 0)),
                'height': float(request.form.get('height', 0)),
                'health_history': request.form.get('health_history', '')
            }

            result = db.add_record(record_data, session['username'])
            if result.get('success'):
                flash('Record added successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash(result.get('message', 'Error adding record.'), 'error')

        except ValueError as ve:
            flash('Please enter valid numerical values for weight and height.', 'error')
        except Exception as e:
            logging.error(f"Error adding record: {str(e)}", exc_info=True)
            flash('An error occurred while adding the record.', 'error')

    return render_template('add_record.html')

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal server error: {str(error)}")
    return render_template('500.html'), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(request.url)


if __name__ == '__main__':
    # Initialize database and create test users if needed
    try:
        db.create_database()
        logging.info("Database initialized successfully")
    except Exception as e:
        logging.error(f"Database initialization error: {str(e)}")

    # Run the application
    app.run(debug=False, host='0.0.0.0', port=5000)