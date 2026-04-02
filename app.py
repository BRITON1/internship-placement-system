from flask import Flask, render_template, request, redirect, url_for
from database.db_connection import get_db_connection
import mysql.connector

app = Flask(__name__)

# =========================
# HOME
# =========================
@app.route('/')
def home():
    return "InternHub running 🚀"


# =========================
# REGISTER
# =========================

# SHOW REGISTER PAGE
@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')


# HANDLE REGISTER
@app.route('/register', methods=['POST'])
def register():
    full_name = request.form['full_name']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']

    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
    INSERT INTO users (full_name, email, password, role)
    VALUES (%s, %s, %s, %s)
    """

    try:
        cursor.execute(query, (full_name, email, password, role))
        conn.commit()
        return "User registered successfully ✅"

    except mysql.connector.errors.IntegrityError:
        return "Email already exists ❌"


# =========================
# LOGIN
# =========================

# SHOW LOGIN PAGE
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')


# HANDLE LOGIN
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM users WHERE email=%s AND password=%s",
        (email, password)
    )

    user = cursor.fetchone()

    if user:
        role = user['role']

        if role == 'student':
            return redirect(url_for('student_dashboard'))
        elif role == 'organization':
            return redirect(url_for('organization_dashboard'))
        elif role == 'supervisor':
            return redirect(url_for('supervisor_dashboard'))
        elif role == 'admin':
            return redirect(url_for('admin_dashboard'))

    else:
        return "Invalid credentials ❌"


# =========================
# DASHBOARDS
# =========================

@app.route('/student/dashboard')
def student_dashboard():
    return render_template('student_dashboard.html')


@app.route('/organization/dashboard')
def organization_dashboard():
    return render_template('organization_dashboard.html')


@app.route('/supervisor/dashboard')
def supervisor_dashboard():
    return render_template('supervisor_dashboard.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')


# =========================
# RUN APP
# =========================
if __name__ == '__main__':
    app.run(debug=True)