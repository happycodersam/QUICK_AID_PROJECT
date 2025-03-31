from flask import Flask, render_template, request, redirect, flash, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Database Connection
def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

# Initialize Database
def init_db():
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')
        conn.commit()

init_db()  # Ensure database setup

# Home Page
@app.route('/')
def home():
    if 'user_id' in session:
        return render_template('index.html', username=session['username'])
    return redirect(url_for('login'))

# Home Remedies Page
@app.route('/home-remedies')
def home_remedies():
    return render_template('homeRemedies.html')

# Physiotherapy Page
@app.route('/physiotherapy')
def physiotherapy():
    return render_template('physiotherapy.html')

# Providing Nurse Page
@app.route('/providing-nurse')
def providing_nurse():
    return render_template('providingNurse.html')

# Nearest Doctor Page
@app.route('/nearest-doctor')
def nearest_doctor():
    return render_template('nearestDr.html')

# Online Appointment Page
@app.route('/online-appointment')
def online_appointment():
    return render_template('onlineAppointment.html')

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        with get_db_connection() as conn:
            cur = conn.cursor()
            try:
                cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                            (username, email, hashed_password))
                conn.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email already registered. Try a different one.', 'error')
    
    return render_template('register.html')

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            flash('Both email and password are required!', 'error')
            return redirect(url_for('login'))

        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, username, password FROM users WHERE email = ?", (email,))
            user = cur.fetchone()

            if user and check_password_hash(user['password'], password):
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash(f'Welcome, {user["username"]}!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid email or password. Try again.', 'error')
    
    return render_template('login.html')

# User Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=session['username'])

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
