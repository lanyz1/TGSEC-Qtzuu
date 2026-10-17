from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'vulnerable-lab-secret-key-change-in-production'

# VULNERABLE: Disable HttpOnly flag to allow JavaScript cookie access for XSS demonstrations
app.config['SESSION_COOKIE_HTTPONLY'] = False
# Also disable Secure flag for local development (remove in production)
app.config['SESSION_COOKIE_SECURE'] = False

# Database initialization
def init_db():
    conn = sqlite3.connect('lab.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT DEFAULT 'user',
                  profile_name TEXT DEFAULT '')''')
    
    # Migrations table (for stored XSS vulnerability)
    c.execute('''CREATE TABLE IF NOT EXISTS migrations
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  description TEXT,
                  created_by INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (created_by) REFERENCES users(id))''')
    
    # Create default users
    c.execute("INSERT OR IGNORE INTO users (username, password, role, profile_name) VALUES (?, ?, ?, ?)",
              ('admin', 'admin123', 'admin', 'Administrator'))
    c.execute("INSERT OR IGNORE INTO users (username, password, role, profile_name) VALUES (?, ?, ?, ?)",
              ('migration_coord', 'coord123', 'Migration Coordinator', 'Migration Coordinator'))
    c.execute("INSERT OR IGNORE INTO users (username, password, role, profile_name) VALUES (?, ?, ?, ?)",
              ('victim', 'victim123', 'user', 'Victim User'))
    
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('lab.db')
        c = conn.cursor()
        c.execute("SELECT id, username, role, profile_name FROM users WHERE username = ? AND password = ?",
                  (username, password))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[2]
            session['profile_name'] = user[3] or ''
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session)

# ============================================
# VULNERABILITY 1: Stored XSS in Migration Title
# ============================================
@app.route('/migrations', methods=['GET', 'POST'])
def migrations():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title', '')
        description = request.form.get('description', '')
        
        # VULNERABLE: No sanitization of title field
        conn = sqlite3.connect('lab.db')
        c = conn.cursor()
        c.execute("INSERT INTO migrations (title, description, created_by) VALUES (?, ?, ?)",
                  (title, description, session['user_id']))
        conn.commit()
        conn.close()
        
        return redirect(url_for('migrations'))
    
    # Get all migrations
    conn = sqlite3.connect('lab.db')
    c = conn.cursor()
    c.execute("""SELECT m.id, m.title, m.description, m.created_at, u.username 
                 FROM migrations m 
                 JOIN users u ON m.created_by = u.id 
                 ORDER BY m.created_at DESC""")
    migrations = c.fetchall()
    conn.close()
    
    return render_template('migrations.html', migrations=migrations, user=session)

# ============================================
# VULNERABILITY 2: Stored XSS in Profile Name
# ============================================
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        profile_name = request.form.get('profile_name', '')
        
        # VULNERABLE: No sanitization of profile_name field
        conn = sqlite3.connect('lab.db')
        c = conn.cursor()
        c.execute("UPDATE users SET profile_name = ? WHERE id = ?",
                  (profile_name, session['user_id']))
        conn.commit()
        conn.close()
        
        session['profile_name'] = profile_name
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=session)

@app.route('/Profile/userProfile')
def user_profile_redirect():
    """Alternative route matching the bug report"""
    return redirect(url_for('profile'))

@app.route('/Profile/userProfileEdit', methods=['POST'])
def user_profile_edit():
    """Vulnerable endpoint matching the bug report"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    profile_name = request.form.get('name', '')
    
    # VULNERABLE: No sanitization
    conn = sqlite3.connect('lab.db')
    c = conn.cursor()
    c.execute("UPDATE users SET profile_name = ? WHERE id = ?",
              (profile_name, session['user_id']))
    conn.commit()
    conn.close()
    
    session['profile_name'] = profile_name
    return jsonify({'success': True, 'name': profile_name})

# ============================================
# VULNERABILITY 3: Reflected XSS in URL Parameter
# ============================================
@app.route('/help')
def help_page():
    """Vulnerable help page with reflected XSS"""
    # VULNERABLE: Directly reflecting URL parameter without sanitization
    url_param = request.args.get('url', '')
    redirect_url = request.args.get('redirect', '')
    # Also check for any query parameter
    search_query = request.args.get('q', '')
    page = request.args.get('page', '')
    
    # VULNERABLE: help.html parameter for iframe injection (matches bug report pattern)
    help_html = ''
    
    # Check if help.html parameter exists (with or without value)
    if 'help.html' in request.args:
        help_html = request.args.get('help.html', '')
        # If help.html parameter exists but is empty, use 'help.html' as default
        if help_html == '':
            help_html = 'help.html'
    else:
        # Try to get raw query string for cases like ?javascript:confirm(1) or ?//evil.com
        query_string = request.query_string.decode('utf-8')
        if query_string:
            # If query string doesn't contain '=', it's likely a raw value
            if '=' not in query_string:
                help_html = query_string
            # If it's a single parameter with a value, use that value
            elif len(request.args) == 1:
                first_param = list(request.args.keys())[0]
                help_html = request.args.get(first_param, '')
    
    # This matches the vulnerability pattern from the bug report
    return render_template('help.html', url_param=url_param, redirect_url=redirect_url, search_query=search_query, page=page, help_html=help_html)

@app.route('/Self-Signup/en_US/index.html')
def self_signup():
    """Vulnerable endpoint matching the bug report pattern"""
    # VULNERABLE: Reflecting query parameter directly
    # Check for URL parameter first (matches bug report)
    param_value = request.args.get('url', '')
    if not param_value:
        # Try to get any query parameter value
        query_string = request.query_string.decode('utf-8')
        if query_string and '=' in query_string:
            param_value = query_string.split('=', 1)[1]
        elif query_string:
            param_value = query_string
    
    return render_template('self_signup.html', param_value=param_value)

@app.route('/home')
def home():
    """Home page with login link"""
    return render_template('home.html')

@app.route('/reset', methods=['POST'])
def reset_app():
    """Reset the app - clear all XSS payloads"""
    conn = sqlite3.connect('lab.db')
    c = conn.cursor()
    
    # Clear all migrations
    c.execute("DELETE FROM migrations")
    
    # Reset all profile names to default
    c.execute("UPDATE users SET profile_name = '' WHERE username = 'admin'")
    c.execute("UPDATE users SET profile_name = 'Migration Coordinator' WHERE username = 'migration_coord'")
    c.execute("UPDATE users SET profile_name = 'Victim User' WHERE username = 'victim'")
    
    # Update session if user is logged in
    if 'user_id' in session:
        c.execute("SELECT profile_name FROM users WHERE id = ?", (session['user_id'],))
        result = c.fetchone()
        if result:
            session['profile_name'] = result[0] or ''
    
    conn.commit()
    conn.close()
    
    return redirect(request.referrer or url_for('index'))

# ============================================
# LAB PAGES - Individual lab entry points
# ============================================
@app.route('/lab/1')
def lab_1():
    """Lab 1: Stored XSS in Migration Title - Redirect to actual app"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('migrations'))

@app.route('/lab/2')
def lab_2():
    """Lab 2: Stored XSS in Profile Name - Redirect to actual app"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('profile'))

@app.route('/lab/3')
def lab_3():
    """Lab 3: Reflected XSS in URL Parameter - Redirect to actual app"""
    # Redirect to help page with a realistic parameter to show it works
    return redirect(url_for('help_page', q='getting-started'))

# ============================================
# SOLUTION PAGES - Educational content
# ============================================
@app.route('/solution/1')
def solution_1():
    """Solution for Lab 1"""
    return render_template('solution_1.html')

@app.route('/solution/2')
def solution_2():
    """Solution for Lab 2"""
    return render_template('solution_2.html')

@app.route('/solution/3')
def solution_3():
    """Solution for Lab 3"""
    return render_template('solution_3.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

