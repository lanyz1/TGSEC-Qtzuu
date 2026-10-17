from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DATABASE = 'bac_lab.db'

def init_db():
    """Initialize the database with users and data"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT DEFAULT 'user',
                  paid INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Add paid column if it doesn't exist (for existing databases)
    try:
        c.execute("ALTER TABLE users ADD COLUMN paid INTEGER DEFAULT 0")
        conn.commit()
        # Update existing admin users to have paid status
        c.execute("UPDATE users SET paid = 1 WHERE role = 'admin' AND paid IS NULL")
        conn.commit()
    except sqlite3.OperationalError:
        # Column already exists, ignore
        pass
    
    # User data table
    c.execute('''CREATE TABLE IF NOT EXISTS user_data
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  data_key TEXT NOT NULL,
                  data_value TEXT,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Admin settings table
    c.execute('''CREATE TABLE IF NOT EXISTS admin_settings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  setting_key TEXT UNIQUE NOT NULL,
                  setting_value TEXT,
                  created_by INTEGER,
                  FOREIGN KEY (created_by) REFERENCES users (id))''')
    
    # Organization data table
    c.execute('''CREATE TABLE IF NOT EXISTS org_data
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  org_name TEXT NOT NULL,
                  api_key TEXT NOT NULL,
                  secret_token TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create default admin user
    admin_hash = generate_password_hash('admin123')
    try:
        c.execute("INSERT INTO users (username, email, password, role, paid) VALUES (?, ?, ?, ?, ?)",
                  ('admin', 'admin@baclab.com', admin_hash, 'admin', 1))
    except sqlite3.IntegrityError:
        pass
    
    # Create test user (not paid)
    user_hash = generate_password_hash('user123')
    try:
        c.execute("INSERT INTO users (username, email, password, role, paid) VALUES (?, ?, ?, ?, ?)",
                  ('user1', 'user1@baclab.com', user_hash, 'user', 0))
        user_id = c.lastrowid
        c.execute("INSERT INTO user_data (user_id, data_key, data_value) VALUES (?, ?, ?)",
                  (user_id, 'secret', 'User secret data - FLAG: BAC_LAB_USER_DATA'))
    except sqlite3.IntegrityError:
        pass
    
    # Add admin settings with flag
    try:
        admin_id = c.execute("SELECT id FROM users WHERE role='admin'").fetchone()[0]
        c.execute("INSERT INTO admin_settings (setting_key, setting_value, created_by) VALUES (?, ?, ?)",
                  ('secret_flag', 'FLAG: BAC_LAB_ADMIN_PANEL_ACCESSED', admin_id))
        c.execute("INSERT INTO admin_settings (setting_key, setting_value, created_by) VALUES (?, ?, ?)",
                  ('api_key', 'ADMIN_API_KEY_2024_SECRET', admin_id))
        
        # Add organization data
        c.execute("INSERT INTO org_data (org_name, api_key, secret_token) VALUES (?, ?, ?)",
                  ('Organization Alpha', 'ORG_ALPHA_API_KEY_XYZ123', 'SECRET_TOKEN_ALPHA_789'))
        c.execute("INSERT INTO org_data (org_name, api_key, secret_token) VALUES (?, ?, ?)",
                  ('Organization Beta', 'ORG_BETA_API_KEY_ABC456', 'SECRET_TOKEN_BETA_012'))
        c.execute("INSERT INTO org_data (org_name, api_key, secret_token) VALUES (?, ?, ?)",
                  ('Organization Gamma', 'ORG_GAMMA_API_KEY_DEF789', 'SECRET_TOKEN_GAMMA_345'))
    except sqlite3.IntegrityError:
        pass
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))
        
        conn = get_db()
        try:
            password_hash = generate_password_hash(password)
            conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                        (username, email, password_hash))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists!', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Welcome back, {user["username"]}!', 'success')
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    conn = get_db()
    user_data = conn.execute("SELECT * FROM user_data WHERE user_id = ?", 
                            (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('dashboard.html', user_data=user_data)

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin':
        flash('Access denied! Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    
    conn = get_db()
    admin_id = conn.execute("SELECT id FROM users WHERE role='admin'").fetchone()
    admin_id = admin_id[0] if admin_id else None
    
    setting_id = request.args.get('id', type=int)
    
    if setting_id:
        settings = conn.execute("SELECT * FROM admin_settings WHERE id = ?", 
                               (setting_id,)).fetchall()
    else:
        settings = conn.execute("SELECT * FROM admin_settings").fetchall()
    
    users = conn.execute("SELECT id, username, email, role, created_at FROM users").fetchall()
    conn.close()
    
    return render_template('admin.html', settings=settings, users=users, admin_id=admin_id)

@app.route('/api/user/<int:user_id>')
def get_user_data(user_id):
    """FIXED: Now properly checks ownership (IDOR fixed for normal users)
    VULNERABILITY: But admins can access any user's data
    If you have admin's session cookie, you can access all users!"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    user = conn.execute("SELECT id, username, email FROM users WHERE id = ?", 
                       (user_id,)).fetchone()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # FIXED: Now checks if user owns the data OR is admin
    # Normal users can only access their own data
    if user_id != session['user_id'] and session.get('role') != 'admin':
        return jsonify({
            'error': 'Forbidden',
            'message': 'You can only access your own data'
        }), 403
    
    user_data = conn.execute("SELECT * FROM user_data WHERE user_id = ?", 
                            (user_id,)).fetchall()
    conn.close()
    
    data = {
        'user': dict(user),
        'data': [dict(d) for d in user_data]
    }
    
    return jsonify(data)

@app.route('/api/admin/settings')
def get_admin_settings():
    """VULNERABILITY: Hidden endpoint not accessible through UI, but if user discovers the path
    via intercepted admin requests, they can access it directly with their own cookie.
    Missing proper authorization check allows any authenticated user to access."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: Only checks if user is logged in, doesn't verify admin role!
    # Any authenticated user can access this if they know the endpoint path
    # Admin UI doesn't expose this endpoint, but direct API access works
    
    conn = get_db()
    settings = conn.execute("SELECT * FROM admin_settings").fetchall()
    conn.close()
    
    return jsonify([dict(s) for s in settings])

@app.route('/api/admin/keys')
def get_admin_api_keys():
    """VULNERABILITY: Hidden endpoint not accessible through UI, but if user discovers the path
    via intercepted admin requests, they can access it directly with their own cookie.
    Missing proper authorization check allows any authenticated user to access."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: Only checks if user is logged in, doesn't verify admin role!
    # Any authenticated user can access this if they know the endpoint path
    # Admin UI doesn't expose this endpoint, but direct API access works
    
    conn = get_db()
    # Get all API keys and organization data
    org_data = conn.execute("SELECT * FROM org_data").fetchall()
    admin_settings = conn.execute("SELECT * FROM admin_settings WHERE setting_key LIKE '%key%' OR setting_key LIKE '%api%'").fetchall()
    conn.close()
    
    return jsonify({
        'admin_api_keys': [dict(s) for s in admin_settings],
        'organization_keys': [dict(o) for o in org_data],
        'message': 'All API keys retrieved successfully'
    })

@app.route('/api/admin/users/all')
def get_all_users_data():
    """VULNERABILITY: Hidden endpoint not accessible through UI, but if user discovers the path
    via intercepted admin requests, they can access it directly with their own cookie.
    Missing proper authorization check allows any authenticated user to access."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: Only checks if user is logged in, doesn't verify admin role!
    # Any authenticated user can access this if they know the endpoint path
    # Admin UI doesn't expose this endpoint, but direct API access works
    
    conn = get_db()
    # Get all users with their sensitive data
    users = conn.execute("SELECT id, username, email, role, created_at FROM users").fetchall()
    
    all_users_data = []
    for user in users:
        user_data = conn.execute("SELECT * FROM user_data WHERE user_id = ?", (user['id'],)).fetchall()
        all_users_data.append({
            'user': dict(user),
            'data': [dict(d) for d in user_data]
        })
    
    conn.close()
    
    return jsonify({
        'users': all_users_data,
        'total_users': len(all_users_data),
        'message': 'All users data retrieved successfully'
    })

@app.route('/update_role', methods=['POST'])
def update_role():
    """VULNERABILITY 5: Privilege escalation - users can change their role"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    target_user_id = request.form.get('user_id', type=int)
    new_role = request.form.get('role')
    
    # VULNERABLE: No admin check, users can escalate their privileges
    if target_user_id and new_role:
        conn = get_db()
        conn.execute("UPDATE users SET role = ? WHERE id = ?", 
                    (new_role, target_user_id))
        conn.commit()
        conn.close()
        
        # Update session if updating own role
        if target_user_id == session['user_id']:
            session['role'] = new_role
            flash('Role updated successfully!', 'success')
            if new_role == 'admin':
                return redirect(url_for('admin_dashboard'))
        
        return redirect(url_for('user_dashboard'))
    
    return redirect(url_for('user_dashboard'))

@app.route('/profile/<int:user_id>')
def profile(user_id):
    """VULNERABILITY 6: IDOR in profile access"""
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    conn = get_db()
    # VULNERABLE: Can view any user's profile by changing user_id
    user = conn.execute("SELECT id, username, email, role, created_at FROM users WHERE id = ?", 
                       (user_id,)).fetchone()
    conn.close()
    
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Show extra info if admin
    is_admin = session.get('role') == 'admin'
    
    return render_template('profile.html', user=dict(user), is_admin=is_admin)

@app.route('/api/user/paid-status')
def get_paid_status():
    """VULNERABILITY: Client-side security - paid status checked on frontend only
    Attacker can intercept response and change paid: false to paid: true"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    user = conn.execute("SELECT paid FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Get paid status from database
    # IMPORTANT: Only return True if paid=1, otherwise always return False
    # This ensures regular users (paid=0) ALWAYS get {"paid": false}
    paid_value = user['paid']
    
    # Explicit check - must be exactly 1 to be True
    if paid_value == 1:
        paid_status = True
    else:
        paid_status = False  # Default: ALL users without paid=1 get False
    
    # VULNERABLE: Returns paid status in API response
    # Frontend trusts this value without server-side verification
    # Attacker can intercept and modify paid: false → paid: true
    # DEFAULT: Regular users MUST ALWAYS get {"paid": false}
    return jsonify({
        'paid': paid_status,  # Will be False for user1 (paid=0 in database)
        'message': 'Premium course access available' if paid_status else 'Upgrade to premium to access course videos'
    })

@app.route('/course')
def course():
    """Course page - checks paid status on frontend"""
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    return render_template('course.html')

@app.route('/api/course/videos')
def get_course_videos():
    """Returns course videos - should check paid status server-side but doesn't"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: Should verify paid status server-side, but doesn't
    # Frontend check can be bypassed by modifying API response
    conn = get_db()
    user = conn.execute("SELECT paid FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    
    # Premium course videos from  channel
    # These videos are only accessible when paid: true in API response
    # VULNERABILITY: Attacker intercepts /api/user/paid-status response
    # Changes "paid": false to "paid": true to get free access
    videos = [
        {
            'id': 1,
            'title': 'Bug Bounty Hunting Tutorial',
            'youtube_id': 'Kl67AXxSEtk',
            'description': 'Learn bug bounty hunting techniques from '
        },
        {
            'id': 2,
            'title': 'Advanced Bug Bounty Exploitation',
            'youtube_id': 'LOgbZajJxKA',
            'description': 'Advanced bug bounty exploitation methods and techniques'
        },
        {
            'id': 3,
            'title': 'Bug Bounty Techniques',
            'youtube_id': 'YF_27RxLOH0',
            'description': 'Advanced bug bounty techniques and vulnerability exploitation'
        }
    ]
    
    return jsonify({
        'videos': videos,
        'premium': bool(user['paid']) if user else False
    })

if __name__ == '__main__':
    init_db()
    print("\n" + "="*50)
    print("BAC LAB - Broken Access Control Lab")
    print("="*50)
    print("\nDefault Credentials:")
    print("Admin: admin / admin123")
    print("User:  user1 / user123")
    print("\nServer running on http://127.0.0.1:5000")
    print("="*50 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)

