import os
import re
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt

app = Flask(__name__)
# Cryptographically secure random key for session signing
app.secret_key = os.urandom(32)
bcrypt = Bcrypt(app)

DB_FILE = 'users.db'

def get_db_connection():
    """Establishes a connection to the SQLite database with row factory enabled."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Creates the user schema safely if it doesn't already exist."""
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()

# --- Input Validation Helpers ---

def validate_user_input(username, email, password):
    """Validates registration fields against security and formatting rules."""
    # Alphanumeric and underscores, 3-20 characters
    if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
        return "Username must be 3-20 characters long (letters, numbers, and underscores only)."
        
    # Standard email format verification
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
        return "Please enter a valid email address."
        
    # Enforce acceptable credential strength
    if len(password) < 8:
        return "Password must be at least 8 characters long."
        
    return None


# --- Controller Routes ---

@app.route('/')
def index():
    """Root route redirecting authenticated users to dashboard or guests to login."""
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles new user onboarding and secure password hashing."""
    if request.method == 'GET':
        return render_template('register.html')

    # Extract and clean form inputs
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')

    # Run structural integrity checks on inputs
    error_message = validate_user_input(username, email, password)
    if error_message:
        flash(error_message, "danger")
        return render_template('register.html')

    # Securely salt and hash the plaintext password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        with get_db_connection() as conn:
            # Parameterized query blocks SQL injection vectors entirely
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, hashed_password)
            )
            conn.commit()
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for('login'))
        
    except sqlite3.IntegrityError:
        flash("That username or email is already registered.", "danger")
        return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticates users securely by verifying salted password hashes."""
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    with get_db_connection() as conn:
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

    # Avoid timing attacks by using a uniform checking method
    if user and bcrypt.check_password_hash(user['password_hash'], password):
        # Prevent session fixation attacks by cycling the session cookie
        session.clear()
        session['username'] = user['username']
        return redirect(url_for('index'))
    
    flash("Invalid username or password configuration.", "danger")
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Clears client session context completely and signs out the user."""
    session.clear()
    flash("You have logged out successfully.", "success")
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_database()
    app.run(debug=True)
