from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from Database import SecureDB, DataConfidentiality, IntegrityProtection, AccessControl
import logging
import os
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s [%(filename)s:%(lineno)d]: %(message)s'
)

app = Flask(__name__)
# Fixed secret key - Don't use os.urandom as it generates new key on restart
app.secret_key = 'your-fixed-secret-key-here'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Initialize database
db = SecureDB()


def init_db():
    """Initialize database and create test users if they don't exist"""
    try:
        conn = db._get_db_connection(db.config.DATABASE)
        cursor = conn.cursor(dictionary=True)

        # Check if admin user exists
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        if not cursor.fetchone():
            # Create admin user
            password_hash = generate_password_hash('Admin@123456')
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, `group`) VALUES (%s, %s, %s, %s)",
                ('admin', password_hash, 'salt', 'H')
            )

        # Check if regular user exists
        cursor.execute("SELECT * FROM users WHERE username = 'regular_user'")
        if not cursor.fetchone():
            # Create regular user
            password_hash = generate_password_hash('Regular@123456')
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, `group`) VALUES (%s, %s, %s, %s)",
                ('regular_user', password_hash, 'salt', 'R')
            )

        conn.commit()
        logging.info("Database initialized successfully")
    except Exception as e:
        logging.error(f"Database initialization error: {str(e)}")
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logging.debug("No user_id in session, redirecting to login")
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_group' not in session or session['user_group'] != 'H':
            logging.debug("Non-admin user attempting to access admin area")
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated_function


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

        logging.debug(f"Login attempt for username: {username}")

        try:
            conn = db._get_db_connection(db.config.DATABASE)
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                "SELECT * FROM users WHERE username = %s",
                (username,)
            )
            user = cursor.fetchone()

            if user and check_password_hash(user['password_hash'], password):
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['user_group'] = user['group']
                session.permanent = True

                logging.debug(f"Login successful for user: {username}")
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'error')
                logging.debug(f"Login failed for username: {username}")

        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            flash('An error occurred during login.', 'error')
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    return render_template('html/login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    try:
        logging.debug(f"Accessing dashboard. Session data: {session}")
        user_data = db.get_user_data(session['username'], session['user_group'])
        return render_template('html/dashboard.html',
                               username=session['username'],
                               user_group=session['user_group'],
                               records=user_data.get('records', []),
                               merkle_root=user_data.get('merkle_root', ''))
    except Exception as e:
        logging.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard data.', 'error')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    logging.debug("User logging out")
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


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
                'weight': request.form.get('weight'),
                'height': request.form.get('height'),
                'health_history': request.form.get('health_history')
            }

            result = db.add_record(record_data, session['username'])
            if result.get('success'):
                flash('Record added successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Error adding record.', 'error')
        except Exception as e:
            logging.error(f"Add record error: {str(e)}")
            flash('Error adding record.', 'error')

    return render_template('html/add_record.html')


@app.route('/view-record/<int:record_id>')
@login_required
def view_record(record_id):
    try:
        conn = db._get_db_connection(db.config.DATABASE)
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT r.*, u.username 
            FROM records r 
            JOIN users u ON r.user_id = u.id 
            WHERE r.id = %s
        """, (record_id,))

        record = cursor.fetchone()

        if not record:
            flash('Record not found.', 'error')
            return redirect(url_for('dashboard'))

        if session['user_group'] != 'H' and record['username'] != session['username']:
            flash('Access denied.', 'error')
            return redirect(url_for('dashboard'))

        return render_template('html/view_record.html', record=record)

    except Exception as e:
        logging.error(f"View record error: {str(e)}")
        flash('Error viewing record.', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()


@app.before_request
def before_request():
    """Ensure user session is still valid"""
    if 'user_id' in session:
        try:
            conn = db._get_db_connection(db.config.DATABASE)
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id FROM users WHERE id = %s", (session['user_id'],))
            if not cursor.fetchone():
                session.clear()
                flash('Session expired. Please login again.', 'error')
                return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Session validation error: {str(e)}")
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()


@app.errorhandler(404)
def not_found_error(error):
    return render_template('html/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal server error: {str(error)}")
    return render_template('html/500.html'), 500


if __name__ == '__main__':
    init_db()  # Initialize database and create test users
    app.run(debug=True)