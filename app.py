import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from utils import get_db_connection
from dotenv import load_dotenv
import traceback

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Use environment variable or a secure key

# Flask-Mail configuration
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True').lower() in ['true', '1', 't'],
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD')
)

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

def send_verification_email(email, verification_url):
    msg = Message('Verify Your Email - DeepGuard Quest', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Please click the following link to verify your email: {verification_url}'
    mail.send(msg)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Validate input lengths
        if len(name) > 100 or len(email) > 100 or len(username) > 100 or len(password) > 100:
            flash('Input values exceed maximum allowed length.', 'error')
            return redirect(url_for('signup'))

        try:
            with get_db_connection() as conn:
                cur = conn.cursor()

                # Check if the email or username already exists
                cur.execute('SELECT * FROM users WHERE email = %s OR username = %s', (email, username))
                existing_user = cur.fetchone()

                if existing_user:
                    flash('Email or username already exists. Please choose another.', 'error')
                    return redirect(url_for('signup'))

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
                return redirect(url_for('login'))

        except Exception as e:
            logging.error(f"Error during signup: {e}")
            logging.error(traceback.format_exc())
            flash('An error occurred during signup. Please try again.', 'error')

    return render_template('signup.html')

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

                if user and check_password_hash(user['password'], password) and user['verified']:
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid username or password.', 'error')

        except Exception as e:
            logging.error(f"Error during login: {e}")
            logging.error(traceback.format_exc())
            flash('An error occurred during login. Please try again.', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('index'))

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
