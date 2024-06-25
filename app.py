import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from utils import get_db_connection
from psycopg2.extras import RealDictCursor
import os
import re
import traceback
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')  # Use environment variable or a secure key

# Flask-Mail configuration
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True').lower() in ['true', '1', 't'],
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD')
)

# Initialize Flask-Mail
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Helper function to send verification email
def send_verification_email(email, verification_url):
    msg = Message('Verify Your Email - DeepGuard Quest', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Please click the following link to verify your email: {verification_url}'
    mail.send(msg)

# Helper function to check password strength
def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""

# Helper function to check valid username format
def is_valid_username(username):
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username can only contain letters, digits, and underscores."
    return True, ""

# Route for the index page
@app.route('/')
def index():
    return render_template('index.html')

# Route for the signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    errors = {}
    name = ''
    email = ''
    username = ''
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Validate input lengths
        if len(name) > 100:
            errors['name'] = 'Name exceeds maximum allowed length.'
        if len(email) > 100:
            errors['email'] = 'Email exceeds maximum allowed length.'
        if len(username) > 100:
            errors['username'] = 'Username exceeds maximum allowed length.'
        
        # Check username validity
        is_valid, username_message = is_valid_username(username)
        if not is_valid:
            errors['username'] = username_message
        
        # Check password strength
        is_strong, password_message = is_strong_password(password)
        if not is_strong:
            errors['password'] = password_message

        if errors:
            return render_template('signup.html', errors=errors, name=name, email=email, username=username)

        try:
            with get_db_connection() as conn:
                cur = conn.cursor()

                # Check if the email or username already exists
                cur.execute('SELECT * FROM users WHERE email = %s OR username = %s', (email, username))
                existing_user = cur.fetchone()

                if existing_user:
                    if existing_user['email'] == email:
                        errors['email'] = 'Email already exists. Please choose another.'
                    if existing_user['username'] == username:
                        errors['username'] = 'Username already exists. Please choose another.'
                    return render_template('signup.html', errors=errors, name=name, email=email, username=username)

                # Hash the password before storing it in the database
                hashed_password = generate_password_hash(password)

                # Generate email verification token
                token = serializer.dumps(email, salt='email-verify')

                # Insert user into database (not verified yet)
                cur.execute('INSERT INTO users (name, email, username, password, verified) VALUES (%s, %s, %s, %s, %s)',
                            (name, email, username, hashed_password, False))
                conn.commit()

                # Send email with verification link
                verification_url = url_for('verify_email', token=token, _external=True)
                send_verification_email(email, verification_url)

                flash('Please check your email to verify your account.', 'success')
                return redirect(url_for('login'))  # Redirect to the login route

        except Exception as e:
            logging.error(f"Error during signup: {e}")
            logging.error(traceback.format_exc())
            flash('An error occurred during signup. Please try again.', 'error')

    return render_template('signup.html', errors=errors, name=name, email=email, username=username)

# Route for verifying email
@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=3600)
    except Exception as e:
        logging.error(f"Error during email verification: {e}")
        logging.error(traceback.format_exc())
        flash('The verification link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    try:
        with get_db_connection() as conn:
            cur = conn.cursor()

            # Mark the user as verified in the database
            cur.execute('UPDATE users SET verified = TRUE WHERE email = %s', (email,))
            conn.commit()

        flash('Your email has been verified. You can now log in.', 'success')
        return redirect(url_for('login'))

    except Exception as e:
        logging.error(f"Error during email verification update: {e}")
        logging.error(traceback.format_exc())
        flash('An error occurred during email verification. Please try again.', 'error')

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            with get_db_connection() as conn:
                cur = conn.cursor(cursor_factory=RealDictCursor)
                cur.execute('SELECT * FROM users WHERE username = %s', (username,))
                user = cur.fetchone()

                if user:
                    if check_password_hash(user['password'], password) and user['verified']:
                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        return redirect(url_for('dashboard'))
                    else:
                        app.logger.debug(f"Password check failed for user: {username}")
                        flash('Invalid username or password.', 'error')
                else:
                    app.logger.debug(f"User not found: {username}")
                    flash('Invalid username or password.', 'error')

        except Exception as e:
            logging.error(f"Error during login: {e}")
            logging.error(traceback.format_exc())
            flash('An error occurred during login. Please try again.', 'error')

    return render_template('login.html')

# Route for logging out
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('index'))

# Route for the dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        try:
            with get_db_connection() as conn:
                cur = conn.cursor(cursor_factory=RealDictCursor)
                cur.execute('SELECT * FROM quests WHERE user_id = %s', (user_id,))
                quests = cur.fetchall()
                return render_template('dashboard.html', quests=quests)
        except Exception as e:
            logging.error(f"Error during dashboard fetch: {e}")
            logging.error(traceback.format_exc())
            flash('An error occurred while fetching dashboard data. Please try again.', 'error')
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
