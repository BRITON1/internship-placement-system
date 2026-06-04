from flask import flash, redirect, url_for, render_template, request
from flask import flash, redirect, url_for, session, request
from flask import flash, redirect, url_for, session, render_template, request
from flask import flash, redirect, url_for, session, render_template
from flask import Flask, render_template, request, redirect, url_for, session
from database.db_connection import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import mysql.connector

# --- 1. APP CONFIGURATION ---
app = Flask(__name__)
app.secret_key = 'f564aa5df65f5fed3071d62875f6ae69'

# Set session timeout to 10 minutes
app.permanent_session_lifetime = timedelta(minutes=10)

# --- 2. SECURITY DECORATORS (The Guards) ---

# General Guard: Just checks if ANY user is logged in


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin Guard: Checks for 'admin' role


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            return "Access Denied: Admins Only. 🚫", 403
        return f(*args, **kwargs)
    return decorated_function

# Supervisor Guard: Checks for 'supervisor' role


def supervisor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'supervisor':
            return "Access Denied: Supervisors Only. 🚫", 403
        return f(*args, **kwargs)
    return decorated_function

# --- 3. SESSION REFRESHER ---


@app.before_request
def handle_session():
    # This keeps the session alive as long as the user is clicking
    session.permanent = True

# --- 4. ROUTES START BELOW ---  # You need this line!


# =========================
# AUDIT LOG FUNCTION
# =========================
def log_action(action, user_email):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "INSERT INTO audit_logs (action, user_email) VALUES (%s, %s)"
        cursor.execute(query, (action, user_email))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"LOGGING ERROR (Non-critical): {e}")


# =========================
# HOME ROUTE
# =========================
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Maps your clean database enum values to your target dashboard endpoints
    dashboards = {
        'student': 'student_dashboard',
        'supervisor': 'supervisor_dashboard',
        'admin': 'admin_dashboard',
        # Maps database 'employer' to your template layout
        'employer': 'organization_dashboard'
    }

    # ==========================================
    # 1. GET REQUEST HANDLER
    # ==========================================
    if request.method == 'GET':
        if session.get('user_id'):
            # MATCH SCHEMA: Check the integer verification status safely
            is_verified = session.get('is_verified')

            # Circuit breaker: If an employer session is unverified (0), kick them out to stop loops
            if is_verified == 0:
                session.clear()
                return render_template('login.html', error="Your account status requires admin verification. ⏳")

            user_role = str(session.get('role', '')).strip().lower()
            return redirect(url_for(dashboards.get(user_role, 'login')))
        return render_template('login.html')

    # ==========================================
    # 2. POST REQUEST HANDLER (AUTHENTICATION)
    # ==========================================
    email = request.form.get('email', '').strip()
    password_candidate = request.form.get('password', '')

    if not email or not password_candidate:
        return render_template('login.html', error="Please enter both email and password.")

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password_candidate):
            clean_role = str(user.get('role', '')).strip().lower()

            # MATCH SCHEMA: Grab the true tinyint status flag (0 or 1). Default to 0 if missing.
            db_verified = user.get('is_verified')
            if db_verified is None:
                db_verified = 0

            # --- SCHEMA-BASED ACCOUNT GATEKEEPERS ---
            # If the user is an employer and is_verified is 0, halt them immediately
            if clean_role == 'employer' and int(db_verified) == 0:
                return render_template('login.html', error="Your organization account is awaiting review and verification by the university admin. ⏳")

            # Custom handling check if your system uses explicit 'rejected' text in the status column
            if str(user.get('status', '')).strip().lower() == 'rejected':
                return render_template('login.html', error="Your account access request has been declined. Contact admin support. ❌")

            # --- VALIDATED SESSION REGISTRATION ---
            session.clear()
            session['user_id'] = user['id']
            session['full_name'] = user['full_name']
            session['role'] = clean_role
            session['email'] = user['email']
            # Keep track of verification state to protect GET calls
            session['is_verified'] = int(db_verified)
            session.permanent = True

            # Use normalized role token for cleaner destination parsing
            return redirect(url_for(dashboards.get(clean_role, 'login')))

        return render_template('login.html', error="Invalid email or password ❌")

    except Exception as e:
        print(f"Login System Error Log: {e}")
        return render_template('login.html', error="A system error occurred. Please try again.")

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
# =========================
# AUTH (REGISTER + LOGIN)
# =========================


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        incoming_role = request.form.get('role', '').strip().lower()

        # 1. FRONTEND TRANSLATION MATRIX: Safely convert form tokens to true DB ENUM values
        role_map = {
            'student': 'student',
            # Translates 'organization' form choice into 'employer' ENUM
            'organization': 'employer',
            'employer': 'employer'
        }

        # Validate that the requested role is explicitly allowed for public signups
        if incoming_role not in role_map:
            return "Unauthorized role selection. ⛔", 403

        db_role = role_map[incoming_role]

        if not full_name or not email or not password:
            return "All registration fields are strictly required. ❌", 400

        # 2. HASHING: Encrypt security credentials securely
        hashed_pw = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # MATCH SCHEMA: Injects db_role ('employer') and explicitly flags status settings
            query = """
                INSERT INTO users (full_name, email, password, role, is_verified, status) 
                VALUES (%s, %s, %s, %s, 0, 'Active')
            """
            cursor.execute(query, (full_name, email, hashed_pw, db_role))
            conn.commit()

            # Optional activity logging hook
            try:
                log_action("User Registered", email)
            except NameError:
                print(f"[LOG] User registered successfully: {email}")

            return redirect(url_for('login'))

        except Exception as e:
            print(f"Database Registration Failure: {e}")
            if conn:
                conn.rollback()
            return f"An error occurred during registration: {e}"
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')
# ========================
# Notifications
# ========================


@app.context_processor
def inject_notifications():
    user_id = session.get('user_id')
    if user_id:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT message, created_at FROM notifications WHERE user_id = %s ORDER BY created_at DESC LIMIT 5", (user_id,))
        notifications = cursor.fetchall()
        cursor.close()
        conn.close()
        return dict(notifications=notifications)
    return dict(notifications=[])

# =========================
# DASHBOARDS
# =========================


@app.route('/student/reports')
def student_reports():
    # Fetch reports from your database here
    # Example: reports = Report.query.filter_by(student_id=current_user.id).all()
    return render_template('student_dashboard.html', reports=[])


@app.route('/student/submit-report', methods=['GET', 'POST'])
def submit_report():
    if request.method == 'POST':
        # Logic to save the report to your database
        return redirect(url_for('student_reports'))
    return render_template('submit_report.html')


# =========================
# STUDENT DASHBOARD
# =========================
@app.route('/student/dashboard')
def student_dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Fetch student's logbook history
        cursor.execute("""
            SELECT activity_date, week_number, status, supervisor_comment, grade
            FROM logbooks
            WHERE student_id = %s
            ORDER BY activity_date DESC
        """, (user_id,))
        logs = cursor.fetchall()

        # 2. Progress Logic
        cursor.execute("""
            SELECT COUNT(DISTINCT week_number) as count 
            FROM logbooks 
            WHERE student_id = %s
        """, (user_id,))
        log_count = cursor.fetchone()['count']

        # 3. Fetch recent notifications
        cursor.execute("""
            SELECT message, created_at 
            FROM notifications 
            WHERE user_id = %s 
            ORDER BY created_at DESC LIMIT 5
        """, (user_id,))
        notifications = cursor.fetchall()

        # 4. User Details
        cursor.execute("SELECT full_name FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        full_name = user_data['full_name'] if user_data else "Student"
        initial = full_name[0].upper() if full_name else "S"

        # 5. Corrected Stats Query
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) as accepted,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
            FROM applications 
            WHERE student_id = %s
        """, (user_id,))
        stats = cursor.fetchone()

        return render_template('student_dashboard.html',
                               logs=logs,
                               log_count=log_count,
                               notifications=notifications,
                               full_name=full_name,
                               initial=initial,
                               app_count=stats['total'] or 0,
                               pending_count=stats['pending'] or 0,
                               accepted_count=stats['accepted'] or 0,
                               rejected_count=stats['rejected'] or 0)

    except Exception as e:
        print(f"Error: {e}")
        return "Internal Server Error", 500
    finally:
        cursor.close()
        conn.close()

# =========================
# STUDENT: NEW LOGBOOK SUBMISSION
# =========================


@app.route('/student/logbook/new', methods=['GET', 'POST'])
def submit_logbook():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    if request.method == 'POST':
        activity_date = request.form.get('activity_date')
        week_num = request.form.get('week_number')
        desc = request.form.get('description')
        challenges = request.form.get('challenges')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check who is assigned as their supervisor
        cursor.execute(
            "SELECT supervisor_id FROM allocations WHERE student_id = %s", (user_id,))
        allocation = cursor.fetchone()

        if allocation:
            sup_id = allocation['supervisor_id']
            query = """INSERT INTO logbooks (student_id, supervisor_id, activity_date, week_number, activity_description, challenges, status)
                       VALUES (%s, %s, %s, %s, %s, %s, 'pending')"""
            cursor.execute(
                query, (user_id, sup_id, activity_date, week_num, desc, challenges))
            conn.commit()

        cursor.close()
        conn.close()
        return redirect(url_for('student_dashboard'))

    return render_template('submit_logbook.html')


@app.route('/student/logbook')
def view_logbook():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT activity_date, week_number, status, supervisor_comment
        FROM logbooks WHERE student_id = %s
        ORDER BY activity_date DESC
    """, (user_id,))
    logs = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('student_dashboard.html', logs=logs)


@app.route('/organization/dashboard')
def organization_dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Fetch User details (Enforcing 'employer' role according to enum schema)
        cursor.execute(
            "SELECT full_name, role, is_verified FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        # Route Guard: If user doesn't exist or isn't an employer, kick them back to login
        if not user or user.get('role') != 'employer':
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        # --- BULLETPROOF LOOP BREAKER GATEKEEPER ---
        if user.get('is_verified') == 0 or user.get('is_verified') is None:
            cursor.close()
            conn.close()
            session.clear()  # Clear the stale session data safely

            # Flash the warning message cleanly to the actual login screen
            flash("Your organization account is currently awaiting review and verification by the university admin. ⏳", "warning")
            # Explicit redirect breaks the 302 loop!
            return redirect(url_for('login'))

        # Generate branding initial safely
        initial = user['full_name'][0].upper(
        ) if user.get('full_name') else "O"

        # 2. Inspect Schema for Column Drift (Checks if column is employer_id or organization_id)
        cursor.execute("""
            SELECT COUNT(*) AS cnt
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'internships'
              AND COLUMN_NAME = 'employer_id'
        """)
        employer_column_exists = cursor.fetchone()['cnt'] > 0
        fk_column = 'employer_id' if employer_column_exists else 'organization_id'

        # 3. Get Open Slots Capacity
        cursor.execute(
            f"SELECT SUM(slots) as total FROM internships WHERE {fk_column} = %s", (user_id,))
        result = cursor.fetchone()
        open_slots = result['total'] if result and result['total'] else 0

        # 4. Get Pending Applications Count
        cursor.execute(f"""
            SELECT COUNT(*) as total FROM applications a
            JOIN internships i ON a.internship_id = i.id
            WHERE i.{fk_column} = %s AND a.status = 'pending'
        """, (user_id,))
        pending_apps = cursor.fetchone()['total'] or 0

        # 5. Get Active Interns Count
        cursor.execute(f"""
            SELECT COUNT(*) as total FROM applications a
            JOIN internships i ON a.internship_id = i.id
            WHERE i.{fk_column} = %s AND a.status = 'accepted'
        """, (user_id,))
        active_interns = cursor.fetchone()['total'] or 0

    except Exception as e:
        print(
            f"--- [CRITICAL ERROR IN ORGANIZATION DASHBOARD] --- Details: {str(e)}")
        open_slots = pending_apps = active_interns = 0
        initial = "O"
    finally:
        cursor.close()
        conn.close()

    return render_template('organization_dashboard.html',
                           open_slots=open_slots,
                           pending_apps=pending_apps,
                           active_interns=active_interns,
                           initial=initial)


# ========================
# SUPERVISORS DASHBOARD
# ========================
# ========================
# SUPERVISORS DASHBOARD
# ========================
@app.route('/supervisor/dashboard')
@supervisor_required
def supervisor_dashboard():
    supervisor_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Initialize chart data to 0 to prevent HTML crashes
    logbook_stats = {'approved': 0, 'pending': 0, 'rejected': 0}

    try:
        # 1. Total Assigned (Your existing logic)
        cursor.execute(
            "SELECT COUNT(*) AS count FROM allocations WHERE supervisor_id = %s", (supervisor_id,))
        assigned_count = cursor.fetchone()['count']

        # 2. Pending Logbook Reviews (Your existing logic)
        cursor.execute("""
            SELECT COUNT(l.id) AS count 
            FROM logbooks l
            JOIN allocations a ON l.student_id = a.student_id
            WHERE a.supervisor_id = %s AND l.status = 'pending'
        """, (supervisor_id,))
        pending_reviews = cursor.fetchone()['count']

        # 3. New Technical Assessments (The JOOUST Requirement)
        cursor.execute(
            "SELECT COUNT(*) AS count FROM assessments WHERE supervisor_id = %s", (supervisor_id,))
        submitted_grades = cursor.fetchone()['count']

        # 4. Avatar Initial
        cursor.execute(
            "SELECT full_name FROM users WHERE id = %s", (supervisor_id,))
        user_data = cursor.fetchone()
        initial = user_data['full_name'][0].upper() if user_data else "S"

        # 5. GRAPHICAL DATA: Logbook Review Progress
        # This fetches the status of all logbooks for students assigned to THIS supervisor
        cursor.execute("""
            SELECT l.status, COUNT(l.id) as count 
            FROM logbooks l
            JOIN allocations a ON l.student_id = a.student_id
            WHERE a.supervisor_id = %s
            GROUP BY l.status
        """, (supervisor_id,))
        status_results = cursor.fetchall()

        for row in status_results:
            status_key = row['status'].lower()
            if status_key in logbook_stats:
                logbook_stats[status_key] = row['count']

        # Return exactly the variables your HTML expects
        return render_template(
            'supervisor_dashboard.html',
            assigned_count=assigned_count,
            pending_reviews=pending_reviews,
            submitted_grades=submitted_grades,
            initial=initial,
            logbook_stats=logbook_stats  # Pass the chart data!
        )

    except Exception as e:
        print(f"Supervisor Dashboard Error: {e}")
        return "Internal Error", 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()
# =========================
# SUPERVISOR: ASSIGNED STUDENTS LIST
# =========================


@app.route('/supervisor/assigned-students')
def assigned_students():
    supervisor_id = session.get('user_id')
    if not supervisor_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 🔍 FIX: Bridge through the intermediate 'students' table to get true user details
    query = """
        SELECT 
            a.id AS allocation_id,
            u.id AS user_id,
            u.full_name, 
            u.email,
            u.role
        FROM allocations a
        JOIN students s ON a.student_id = s.id
        JOIN users u ON s.user_id = u.id
        WHERE a.supervisor_id = %s
    """
    cursor.execute(query, (supervisor_id,))
    students = cursor.fetchall()

    # Get Initial for sidebar
    cursor.execute("SELECT full_name FROM users WHERE id = %s",
                   (supervisor_id,))
    sup = cursor.fetchone()
    initial = sup['full_name'][0].upper() if sup else "S"

    cursor.close()
    conn.close()

    return render_template('assigned_students.html', students=students, initial=initial)


@app.route('/supervisor/assigned_evaluations')
@supervisor_required
def supervisor_evaluations():
    supervisor_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT
            e.id AS eval_id,
            u.full_name AS student_name,
            org.full_name AS org_name,
            i.title,
            e.recommendation
        FROM evaluations e
        JOIN placements p ON e.placement_id = p.id
        JOIN users u ON p.student_id = u.id
        LEFT JOIN internships i ON p.internship_id = i.id
        LEFT JOIN users org ON i.organization_id = org.id
        WHERE p.supervisor_id = %s
        ORDER BY e.created_at DESC
    """

    try:
        cursor.execute(query, (supervisor_id,))
        evaluations = cursor.fetchall()
        cursor.execute("SELECT full_name FROM users WHERE id = %s", (supervisor_id,))
        user = cursor.fetchone()
        initial = user['full_name'][0].upper() if user else 'S'
        return render_template('supervisor_evaluations.html', evaluations=evaluations, initial=initial)
    except Exception as e:
        print(f"Supervisor evaluations error: {e}")
        return "Internal Error", 500
    finally:
        cursor.close()
        conn.close()

# =========================
# LOGBOOK: STUDENT SUBMISSION
# =========================


# =========================
# LOGBOOK: SUPERVISOR VIEW & APPROVE
# =========================


@app.route('/supervisor/logbooks')
@app.route('/supervisor/logbooks/<int:student_id>')
def view_student_logs(student_id=None):
    supervisor_id = session.get('user_id')
    if not supervisor_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch all logs from students assigned to THIS supervisor
    query = """
        SELECT l.*, u.full_name as student_name 
        FROM logbooks l
        JOIN allocations a ON l.student_id = a.student_id
        JOIN users u ON l.student_id = u.id
        WHERE a.supervisor_id = %s
    """
    params = [supervisor_id]
    if student_id:
        query += " AND l.student_id = %s"
        params.append(student_id)

    query += " ORDER BY l.activity_date DESC"
    cursor.execute(query, tuple(params))
    logs = cursor.fetchall()

    # Get initial for sidebar
    cursor.execute("SELECT full_name FROM users WHERE id = %s",
                   (supervisor_id,))
    user = cursor.fetchone()
    initial = user['full_name'][0].upper() if user else "S"

    cursor.close()
    conn.close()
    return render_template('supervisor_logbooks.html', logs=logs, initial=initial)


@app.route('/supervisor/approve_logbook/<int:log_id>', methods=['POST'])
def approve_logbook(log_id):
    supervisor_id = session.get('user_id')
    if not supervisor_id:
        return redirect(url_for('login'))

    # Get form data
    status = request.form.get('status')  # e.g., 'approved' or 'revision'
    comment = request.form.get('comment')
    grade = request.form.get('grade')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1. First, find out the student_id associated with this logbook
    cursor.execute("SELECT student_id FROM logbooks WHERE id = %s", (log_id,))
    log_entry = cursor.fetchone()

    if log_entry:
        student_id = log_entry['student_id']

        # 2. Update the logbook with the grade and comment
        cursor.execute("""
            UPDATE logbooks 
            SET status = %s, supervisor_comment = %s, grade = %s 
            WHERE id = %s
        """, (status, comment, grade, log_id))

        # 3. Insert the notification for the student
        notification_msg = f"Your logbook has been {status}. Grade: {grade}/10."
        cursor.execute(
            "INSERT INTO notifications (user_id, message) VALUES (%s, %s)",
            (student_id, notification_msg)
        )

        conn.commit()

    cursor.close()
    conn.close()

    # Redirect back to the list of students or logbooks
    return redirect(url_for('supervisor_dashboard'))


# 1. VIEW ASSESSMENTS
@app.route('/supervisor/assessments')
@login_required
def view_assessments():
    supervisor_id = session.get('user_id')

    # Security Check
    if session.get('role') != 'supervisor':
        return "Access Denied", 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Fetch assessments with Student Names
        # We use 'a.created_at' as 'assessment_date' so your HTML template doesn't break
        query = """
            SELECT 
                a.id,
                a.score,
                a.remarks,
                a.assessment_date,
                u.full_name as student_name
            FROM assessments a
            JOIN allocations al ON a.placement_id = al.id
            JOIN students s ON al.student_id = s.id
            JOIN users u ON s.user_id = u.id
            WHERE a.supervisor_id = %s
            ORDER BY a.assessment_date DESC
        """
        cursor.execute(query, (supervisor_id,))
        assessments = cursor.fetchall()

        # 2. Get Supervisor's Name for the avatar initial
        cursor.execute(
            "SELECT full_name FROM users WHERE id = %s", (supervisor_id,))
        user_row = cursor.fetchone()

        # Safe way to get initial
        full_name = user_row['full_name'] if user_row else "Supervisor"
        initial = full_name[0].upper()

        return render_template('supervisor_assessments.html',
                               assessments=assessments,
                               initial=initial)
    except Exception as e:
        print(f"Error fetching assessments: {e}")
        return f"Database Error: {e}", 500
    finally:
        cursor.close()
        conn.close()


@app.route('/supervisor/assessment/new', methods=['GET', 'POST'])
@login_required
def new_assessment():
    supervisor_id = session.get('user_id')
    if not supervisor_id or session.get('role') != 'supervisor':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        allocation_id = request.form.get('allocation_id')
        attendance = float(request.form.get('attendance', 0) or 0)
        skills = float(request.form.get('skills', 0) or 0)
        attitude = float(request.form.get('attitude', 0) or 0)
        overall = float(request.form.get('overall', 0) or 0)
        comments = request.form.get('comments', '').strip()

        if not allocation_id:
            cursor.close()
            conn.close()
            return "Missing student assignment ID", 400

        cursor.execute(
            "SELECT full_name FROM users WHERE id = %s", (supervisor_id,))
        supervisor = cursor.fetchone()
        supervisor_name = supervisor['full_name'] if supervisor else 'Supervisor'
        total_score = attendance + skills + attitude + overall

        cursor.execute(
            "INSERT INTO assessments (placement_id, supervisor_name, score, remarks, assessment_date, supervisor_id) VALUES (%s, %s, %s, %s, %s, %s)",
            (allocation_id, supervisor_name, total_score,
             comments, datetime.now().date(), supervisor_id)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('view_assessments'))

    # GET: Populate the student allocation dropdown for this supervisor
    cursor.execute("""
        SELECT
            a.id AS allocation_id,
            u.id AS user_id,
            u.full_name
        FROM allocations a
        JOIN students s ON a.student_id = s.id
        JOIN users u ON s.user_id = u.id
        WHERE a.supervisor_id = %s
    """, (supervisor_id,))
    students = cursor.fetchall()

    selected_allocation = request.args.get('allocation_id')

    cursor.execute("SELECT full_name FROM users WHERE id = %s",
                   (supervisor_id,))
    user_row = cursor.fetchone()
    initial = user_row['full_name'][0].upper() if user_row else 'S'

    cursor.close()
    conn.close()
    return render_template('new_assessment.html', students=students, initial=initial, selected_allocation=selected_allocation)


@app.route('/supervisor/assessment/view/<int:assessment_id>')
@login_required
def view_assessment_detail(assessment_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT a.*, u.full_name as student_name
        FROM assessments a
        JOIN allocations al ON a.placement_id = al.id
        JOIN students s ON al.student_id = s.id
        JOIN users u ON s.user_id = u.id
        WHERE a.id = %s
    """
    cursor.execute(query, (assessment_id,))
    assessment = cursor.fetchone()

    cursor.close()
    conn.close()

    if not assessment:
        return "Assessment not found", 404

    return render_template('assessment_detail.html', assessment=assessment)


# =========================
# SUPERVISOR: PROFILE
# =========================


@app.route('/supervisor/profile', methods=['GET', 'POST'])
def supervisor_profile():
    supervisor_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        # Get data from the profile form
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        full_name = f"{first_name} {last_name}"
        email = request.form.get('email')

        # Update the users table
        query = "UPDATE users SET full_name = %s, email = %s WHERE id = %s"
        cursor.execute(query, (full_name, email, supervisor_id))
        conn.commit()

        # Log the update in audit logs
        log_action("Profile Updated", email)

        return redirect(url_for('supervisor_profile'))

    # Fetch current details to display in the form
    cursor.execute(
        "SELECT full_name, email FROM users WHERE id = %s", (supervisor_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user:
        # Split full name back into first and last for the input boxes
        name_parts = user['full_name'].split(' ')
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else ""
        initial = user['full_name'][0].upper() if user['full_name'] else "S"

        return render_template('supervisor_profile.html',
                               user=user,
                               first_name=first_name,
                               last_name=last_name,
                               initial=initial)

    return "Supervisor not found", 404

# =========================
# ORGANIZATION: POST INTERNSHIP
# =========================


@app.route('/organization/post', methods=['GET', 'POST'])
def manage_slots():
    user_id = session.get('user_id')
    company = session.get('company_name', 'Organization')

    if not user_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # --- 1. VERIFICATION CHECK GUARD ---
    try:
        # Check user account role and status
        cursor.execute(
            "SELECT is_verified, role, full_name FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user or user.get('role') != 'employer':
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        if user.get('is_verified') == 0 or user.get('is_verified') is None:
            cursor.close()
            conn.close()
            session.clear()
            flash("Your organization account is currently awaiting review and verification by the university admin. ⏳", "warning")
            return redirect(url_for('login'))

    except Exception as e:
        print(f"❌ Verification guard database failure: {e}")
        cursor.close()
        conn.close()
        return "Internal authentication error. Try again.", 500

    # --- 2. PART 1: HANDLE NEW SLOT POSTS (POST) ---
    if request.method == 'POST':
        try:
            # Check if a matching row exists in the organizations table
            cursor.execute(
                "SELECT id FROM organizations WHERE user_id = %s", (user_id,))
            org_row = cursor.fetchone()

            # 🚀 SELF-HEALING FALLBACK: If the profile row is missing after the crash, create it dynamically!
            if not org_row:
                print(
                    f"🔧 Profile missing for User ID {user_id}. Creating fallback organization record...")
                insert_org_query = """
                    INSERT INTO organizations (user_id, company_name, status) 
                    VALUES (%s, %s, 'Active')
                """
                cursor.execute(insert_org_query, (user_id, company))
                conn.commit()

                # Fetch the newly created organization ID
                cursor.execute(
                    "SELECT id FROM organizations WHERE user_id = %s", (user_id,))
                org_row = cursor.fetchone()

            db_org_id = org_row['id']  # This matches the parent id constraint

            title = request.form.get('title')
            description = request.form.get('description')
            location = request.form.get('location')
            duration = request.form.get('duration')
            requirements = request.form.get('requirements')

            raw_slots = request.form.get('available_slots')
            slots = int(raw_slots) if raw_slots and raw_slots.isdigit() else 1

            deadline = request.form.get('end_date')
            if not deadline or deadline.strip() == "":
                deadline = None

            # SQL Insertion cleanly targeting your actual 12 columns
            query = """
                INSERT INTO internships 
                (employer_id, organization_id, title, description, location, 
                 slots, duration, requirements, deadline, status) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'Open')
            """
            values = (db_org_id, db_org_id, title, description,
                      location, slots, duration, requirements, deadline)

            cursor.execute(query, values)
            conn.commit()
            print("====> ✅ INSERTS INTO INTERNSHIPS TABLE SUCCESSFUL! <====")

            cursor.close()
            conn.close()
            return redirect(url_for('manage_slots'))

        except Exception as e:
            print(f"❌ CRITICAL DATABASE INSERTION ERROR: {e}")
            try:
                conn.rollback()
                cursor.close()
                conn.close()
            except:
                pass
            flash("Failed to save internship post. Check logs.", "error")
            return redirect(url_for('manage_slots'))

    # --- 3. PART 2: FETCH POSTED INTERNSHIPS (GET) ---
    slots_data = []
    try:
        cursor.execute(
            "SELECT id FROM organizations WHERE user_id = %s", (user_id,))
        org_row = cursor.fetchone()

        if org_row:
            db_org_id = org_row['id']
            # Fetch slots associated with this newly resolved or existing organization row ID
            query = "SELECT * FROM internships WHERE employer_id = %s ORDER BY posted_at DESC"
            cursor.execute(query, (db_org_id,))
            slots_data = cursor.fetchall()
    except Exception as e:
        print(f"❌ SQL Fetch Error: {e}")
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    initial = company[0].upper() if (company and len(company) > 0) else "O"

    return render_template(
        'manage_slots.html',
        slots=slots_data,
        initial=initial
    )


@app.route('/organization/new_slot')
def post_internship_page():
    # This renders the clean form page from your second screenshot
    return render_template('post_internship.html')

    # ✅ LOG ACTION
    log_action("Internship Posted", company_name)

    cursor.close()
    conn.close()

    return redirect(url_for('organization_dashboard'))


# =========================
# STUDENT: VIEW INTERNSHIPS
# =========================

@app.route('/internships')
@app.route('/student/browse_opportunities')
def view_internship():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 🚀 PERFECTLY ALIGNED QUERY:
        # 1. Links internship employer_id to organizations.id (Matches your new ALTER TABLE constraint!)
        # 2. Links organizations.user_id to users.id to check verification status and pull names
        query = """
            SELECT 
                i.*, 
                COALESCE(o.company_name, u.full_name, 'Registered Employer') AS company_name
            FROM internships i
            JOIN organizations o ON i.employer_id = o.id
            JOIN users u ON o.user_id = u.id
            WHERE u.is_verified = 1
              AND LOWER(i.status) = 'open'
            ORDER BY i.posted_at DESC
        """
        cursor.execute(query)
        internships = cursor.fetchall()

        # Fetch what this specific student has already applied for to handle button states
        cursor.execute(
            "SELECT internship_id FROM applications WHERE student_id = %s", (
                user_id,)
        )
        applied_ids = [row['internship_id'] for row in cursor.fetchall()]

    except Exception as e:
        print(f"❌ Error loading internship opportunities for students: {e}")
        internships = []
        applied_ids = []
    finally:
        # Always disconnect safely
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return render_template(
        'view_internships.html',
        internships=internships,
        applied_ids=applied_ids
    )

# =========================
# STUDENT: APPLY FOR INTERNSHIP
# =========================


@app.route('/apply', methods=['POST'])
def apply():
    user_id = session.get('user_id')
    role = session.get('role')

    # 1. Quick Authentication Check
    if not user_id:
        flash("Please login to submit applications.", "warning")
        return redirect(url_for('login'))

    if role != 'student':
        flash("Only student accounts can apply for internship openings.", "error")
        return redirect(url_for('view_internship'))

    internship_id = request.form.get('internship_id')
    if not internship_id:
        flash("Invalid application request parameter.", "error")
        return redirect(url_for('view_internship'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 2. BULLETPROOF DUPLICATE GUARD
        # Checks both columns just in case to safely intercept duplicate row records
        check_query = """
            SELECT id FROM applications 
            WHERE (student_id = %s OR user_id = %s) AND internship_id = %s
        """
        cursor.execute(check_query, (user_id, user_id, internship_id))
        existing = cursor.fetchone()

        if existing:
            flash(
                "You have already submitted an application for this position! ⚠️", "info")
            cursor.close()
            conn.close()
            return redirect(url_for('view_internship'))

        # 3. SELF-HEALING COLUMN INSERTION
        # Inserts into both user_id and student_id to fully satisfy your multi-route query joins.
        # We store status as 'Pending' with capital 'P' or 'pending' lowercase based on your schema preference.
        insert_query = """
            INSERT INTO applications (user_id, student_id, internship_id, status, applied_at)
            VALUES (%s, %s, %s, 'Pending', NOW())
        """
        cursor.execute(insert_query, (user_id, user_id, internship_id))
        conn.commit()

        print(
            f"====> ✅ SUCCESSFUL APPLICATION: Student ID {user_id} registered to Position ID {internship_id} <====")
        flash("Application submitted successfully! Track its status on your dashboard. 🚀", "success")

        # 4. RUN ACTION LOGGER (If your app has it)
        try:
            log_action("Applied for Internship", user_id)
        except NameError:
            pass  # Skips if function log_action is defined in another module block

    except Exception as e:
        print(f"❌ DATABASE ERROR IN APPLY ROUTE: {e}")
        try:
            conn.rollback()
        except:
            pass
        flash("Database Error: Could not process application. Please check system logs.", "error")

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    # 5. FIXED REDIRECT (Points to your actual view function name for /student/browse_opportunities)
    return redirect(url_for('view_internship'))


# =========================
# ORGANIZATION: VIEW APPLICANTS
# =========================

@app.route('/organization/applicants')
def view_applicants():
    user_id = session.get('user_id')
    role = session.get('role')

    # 1. Access Control Guard
    if not user_id:
        return redirect(url_for('login'))

    if role != 'organization' and role != 'employer':
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    applications = []
    status_counts = {'pending': 0, 'approved': 0, 'rejected': 0}

    try:
        # 2. Fetch the organization ID linked to the logged-in user account
        cursor.execute(
            "SELECT id FROM organizations WHERE user_id = %s", (user_id,))
        org_row = cursor.fetchone()

        if not org_row:
            return render_template(
                'view_applicants.html',
                applications=[],
                status_counts=status_counts
            )

        db_org_id = org_row['id']

        # 3. CLEAN BASE QUERY
        query = """
            SELECT 
                a.id AS application_id,
                COALESCE(a.status, 'pending') AS db_status,
                COALESCE(a.applied_at, a.created_at) AS raw_date,
                i.title AS internship_title,
                COALESCE(u.full_name, u2.full_name, 'Assigned Student') AS student_name,
                COALESCE(u.email, u2.email, 'N/A') AS student_email
            FROM applications a
            JOIN internships i ON a.internship_id = i.id
            LEFT JOIN users u ON (a.student_id = u.id OR a.user_id = u.id)
            LEFT JOIN students s ON a.student_id = s.id
            LEFT JOIN users u2 ON s.user_id = u2.id
            WHERE i.employer_id = %s
            ORDER BY a.id DESC
        """
        cursor.execute(query, (db_org_id,))
        raw_applications = cursor.fetchall()

        # 4. EXPLICIT STATUS AND INTERFACE CONTROL INJECTION
        for app_row in raw_applications:
            # Safe Date Conversion
            dt = app_row.get('raw_date')
            app_row['applied_at'] = dt.strftime(
                '%Y-%m-%d %H:%M:%S') if dt else "N/A"

            # Clean and normalize status for counter logic
            raw_status = str(app_row.get(
                'db_status', 'pending')).strip().lower()

            # Absolute mapping to prevent miscellaneous states from messing up metrics
            if 'accept' in raw_status or 'approve' in raw_status:
                clean_status = 'approved'
                app_row['can_action'] = False
            elif 'reject' in raw_status:
                clean_status = 'rejected'
                app_row['can_action'] = False
            else:
                clean_status = 'pending'
                # ONLY pending rows can be accepted/rejected
                app_row['can_action'] = True

            # Force inject exact string values to satisfy any variant the HTML might match against
            # "Pending", "Approved", "Rejected"
            app_row['application_status'] = clean_status.capitalize()
            # "pending", "approved", "rejected"
            app_row['status_clean'] = clean_status

            # Update dashboard stat count cards
            if clean_status in status_counts:
                status_counts[clean_status] += 1

            applications.append(app_row)

        print(
            f"====> ✅ PIPELINE STABILIZED: Found {status_counts['pending']} true pending rows <====")

    except Exception as e:
        print(f"❌ CRITICAL ERROR LOADING APPLICANTS DASHBOARD: {e}")
        applications = []
        status_counts = {'pending': 0, 'approved': 0, 'rejected': 0}

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return render_template(
        'view_applicants.html',
        applications=applications,
        status_counts=status_counts
    )


# =======================
# ADMIN: STUDENTS
# =======================
@app.route('/admin/students')
def admin_students():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT id, full_name, email FROM users WHERE role='student'")
    students = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin_students.html', students=students)

# ========================
# ADMIN VERIFY
# ========================


@app.route('/admin/verify-org/<int:org_id>', methods=['POST'])
def verify_organization(org_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # THE FIX: Explicitly set is_verified to 1 AND status to 'Active'
        # This guarantees the login route recognizes them as fully verified!
        query = """
            UPDATE users 
            SET is_verified = 1, status = 'Active' 
            WHERE id = %s AND role = 'employer'
        """
        cursor.execute(query, (org_id,))
        conn.commit()
        print(
            f"--- [SUCCESS] Organization ID {org_id} has been fully verified and activated! ---")

    except Exception as e:
        print(f"Verification query execution failure: {e}")
        if conn:
            conn.rollback()
    finally:
        cursor.close()
        conn.close()

    # Redirect back to the list layout to see the badge shift live
    return redirect(url_for('admin_organizations'))
# ADMIN: ORGANIZATIONS
# ========================


@app.route('/admin/organizations')
def admin_organizations():
    # Route guard to ensure only admins have access
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Refined to pull exact schema columns matching 'employer' ENUM
        query = """
            SELECT 
                id, 
                full_name, 
                email, 
                role, 
                is_verified,
                COALESCE(NULLIF(TRIM(status), ''), 'Active') AS status
            FROM users 
            WHERE role = 'employer'
            ORDER BY full_name ASC
        """
        cursor.execute(query)
        orgs = cursor.fetchall()

        # Debug helper: Prints to your terminal to track live records cleanly
        print(f"--- [DEBUG] Admin Organizations Found: {len(orgs)} ---")
        for o in orgs:
            print(
                f"ID: {o['id']} | Name: {o['full_name']} | Verified: {o['is_verified']} | Status: {o['status']}")

    except Exception as e:
        print(f"Error fetching organizations: {e}")
        orgs = []
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    # Pass the list to your HTML template matching variable name context
    return render_template('admin_organizations.html', organizations=orgs)
# ========================
# ADMIN: AUDIT LOGS (REAL)
# ========================


@app.route('/admin/audit-logs')
def admin_audit_logs():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM audit_logs ORDER BY created_at DESC")
    logs = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin_audit_logs.html', logs=logs)


# =========================
# ADMIN DASHBOARD
# =========================
@app.route('/admin/dashboard')
@admin_required  # The security lock remains
def admin_dashboard():
    # 1. Initialize all variables (Preventing Undefined Variable Errors)
    students_count = 0
    organizations_count = 0
    placed_count = 0
    pending_count = 0
    supervisors_list = []
    students_list = []

    # Initialize chart data with 0s to prevent front-end crashes if tables are empty
    chart_data = {'pending': 0, 'accepted': 0, 'rejected': 0}

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # --- SECTION A: THE COUNTS ---
        cursor.execute(
            "SELECT COUNT(*) AS count FROM users WHERE role='student'")
        students_count = cursor.fetchone()['count']

        cursor.execute(
            "SELECT COUNT(*) AS count FROM users WHERE role='employer'")
        organizations_count = cursor.fetchone()['count']

        cursor.execute(
            "SELECT COUNT(*) AS count FROM applications WHERE status='accepted'")
        placed_count = cursor.fetchone()['count']

        cursor.execute(
            "SELECT COUNT(*) AS count FROM applications WHERE status='pending'")
        pending_count = cursor.fetchone()['count']

        # --- SECTION B: DATA FOR ASSIGNMENT ---
        cursor.execute(
            "SELECT id, full_name FROM users WHERE role='supervisor'")
        supervisors_list = cursor.fetchall()

        cursor.execute("SELECT id, full_name FROM users WHERE role='student'")
        students_list = cursor.fetchall()

        # --- SECTION C: CHART LOGIC (THE NEW UPGRADE) ---
        # Fetch status distribution for real-time graphics
        cursor.execute(
            "SELECT status, COUNT(*) as count FROM applications GROUP BY status")
        status_results = cursor.fetchall()

        for row in status_results:
            # We use .lower() to ensure the database string matches our dictionary key
            status_key = row['status'].lower()
            if status_key in chart_data:
                chart_data[status_key] = row['count']

        cursor.close()

    except Exception as e:
        print(f"Admin Dashboard Database Error: {e}")
        # We don't return an error page here so the dashboard still loads with 0s
    finally:
        if conn and conn.is_connected():
            conn.close()

    # 2. Pass everything back to the HTML
    return render_template(
        'admin_dashboard.html',
        students=students_count,        # For stat cards
        organizations=organizations_count,
        placed=placed_count,
        pending=pending_count,
        supervisors=supervisors_list,   # For the supervisor dropdown
        students_list=students_list,    # For the student dropdown
        chart_data=chart_data           # FOR THE NEW GRAPH MODULE
    )
# =========================
# APPLICATION STATUS UPDATE (ACCEPT/REJECT)
# =========================


@app.route('/application/update', methods=['POST'])
def update_application():
    # 1. Get the application ID and the chosen status ('accepted' or 'rejected') from the form
    app_id = request.form.get('app_id')
    new_status = request.form.get('status')

    # 2. Establish your SQL connection
    # Note: Use your existing connection logic (e.g., mysql.connector)
    db = get_db_connection()
    cursor = db.cursor()

    try:
        # 3. Update the 'applications' table.
        # This is the "Single Source of Truth" that both the Org and Student see.
        query = "UPDATE applications SET status = %s WHERE id = %s"
        cursor.execute(query, (new_status, app_id))

        # 4. Commit changes so they are saved permanently in the database
        db.commit()
        print(f"Status Synchronized: Application {app_id} is now {new_status}")

    except Exception as e:
        print(f"Update failed: {e}")
        db.rollback()
    finally:
        cursor.close()
        db.close()

    # 5. Redirect back to the applicants list to refresh the view
    return redirect('/organization/applicants')

# =========================
# FEATURES PAGE
# =========================


@app.route('/features')
def features():
    return render_template('features.html')

# =========================
# USER-ROLES
# =========================


@app.route('/user-roles')
def user_roles():
    return render_template('user-roles.html')

# ==========================
# HOW-IT-WORKS
# ==========================


@app.route('/how-it-works')
def how_it_works():
    return render_template('how-it-works.html')

# =========================
# INDEX PAGE SLIDING
# =========================


@app.route('/')
@app.route('/features')
@app.route('/user-roles')
@app.route('/how-it-works')
def index():
    return render_template('index.html')

# =========================
# LOGOUT
# =========================


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# =========================
# STUDENT PROFILE
# =========================


@app.route('/student/profile')
@login_required  # The Shield: Blocks access if no user_id is in session
def student_profile():
    # 1. Retrieve the email we stored during login
    # If this is missing, the redirect below handles it
    user_email = session.get('email')

    # Refresh the 10-minute timeout timer
    session.permanent = True

    user = None
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 2. Fetch only the data we need for the profile
        cursor.execute(
            "SELECT full_name, email, role FROM users WHERE email = %s",
            (user_email,)
        )
        user = cursor.fetchone()
        cursor.close()

    except Exception as e:
        # Professional error handling (visible in your terminal)
        print(f"CRITICAL: Profile Database Error: {e}")
        return "Internal Server Error 500", 500
    finally:
        # Ensure the XAMPP/MySQL connection is closed properly
        if conn and conn.is_connected():
            conn.close()

    # 3. Logic for the User Interface (UI)
    if user:
        # Create a dynamic avatar initial (e.g., "B" for Briton)
        full_name = user['full_name'].strip()
        initial = full_name[0].upper() if full_name else "U"

        # Split names safely: Handles "Briton", "Briton Chadiku", or "Briton Chadiku Amolo"
        name_parts = full_name.split(' ')
        first_name = name_parts[0]
        # Joins all remaining parts as the last name
        last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""

        return render_template('student_profile.html',
                               user=user,
                               first_name=first_name,
                               last_name=last_name,
                               initial=initial)

    # 4. Safety Net: If user session exists but email isn't in DB
    session.clear()
    return redirect(url_for('login'))
# =========================
# STUDENT APPLICATIONS
# =========================


@app.route('/student/applications')
def student_applications():
    # 1. Session Protection: Ensure user is logged in
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # Initialize variables to prevent "referenced before assignment" crashes
    apps = []
    initial = "S"
    conn = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 2. Optimized Query: Use LEFT JOIN and dual-ID check
        # This ensures that even if a company profile is missing, the app shows up.
        # It also checks both ID columns to prevent the "empty window" issue.
        query = """
        SELECT 
            a.status, 
            a.created_at AS applied_date, 
            i.title, 
            i.location,
            i.description,
            u.full_name AS company_name
        FROM applications a
        JOIN internships i ON a.internship_id = i.id
        LEFT JOIN users u ON i.organization_id = u.id
        WHERE a.user_id = %s OR a.student_id = %s
        ORDER BY a.created_at DESC
        """
        cursor.execute(query, (user_id, user_id))
        apps = cursor.fetchall()

        # 3. Avatar Context: Get the user's name safely
        cursor.execute("SELECT full_name FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        if user_data and user_data['full_name']:
            initial = user_data['full_name'][0].upper()

        cursor.close()

    except Exception as e:
        # This catches database crashes and prints the error instead of breaking the site
        print(f"CRITICAL DATABASE ERROR: {e}")
        # 'apps' is already an empty list, so the page will simply say "No applications found"

    finally:
        # 4. Safe Closure: Always close the connection if it was opened
        if conn and conn.is_connected():
            conn.close()

    # 5. Delivery: Using 'apps' to match your HTML {% for app in apps %}
    return render_template('student_applications.html',
                           apps=apps,
                           initial=initial)


# ===========================
#
# ==========================

# =========================
# ORGANIZATION PROFILE
# =========================


@app.route('/organization/profile', methods=['GET', 'POST'])
def company_profile():
    company_name = session.get('company_name')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        # Get data from the form
        industry = request.form.get('industry')
        location = request.form.get('location')
        website = request.form.get('website')
        description = request.form.get('description')
        email = request.form.get('email')
        phone = request.form.get('phone')

        # Update the database
        query = """
            UPDATE users 
            SET industry=%s, location=%s, website=%s, description=%s, contact_email=%s, contact_phone=%s 
            WHERE full_name=%s
        """
        cursor.execute(query, (industry, location, website,
                       description, email, phone, company_name))
        conn.commit()
        return redirect(url_for('company_profile'))

    # Fetch profile to check if it's already filled
    cursor.execute("SELECT * FROM users WHERE full_name = %s", (company_name,))
    profile = cursor.fetchone()

    initial = company_name[0].upper() if company_name else "T"

    cursor.close()
    conn.close()

    # Logic to decide if we show the form or the clean view
    is_complete = True if profile and profile.get('industry') else False

    return render_template('company_profile.html', profile=profile, initial=initial, is_complete=is_complete)


# =====================
# ADMIN SETTINGS
# =====================
@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if request.method == 'POST':
        # logic to update your global settings table or config file
        reg_status = request.form.get('reg_status')
        deadline = request.form.get('global_deadline')

        # Flash a success message
        return redirect(url_for('admin_settings'))

    return render_template('admin_settings.html')

# =========================
# ADMIN REPORTS
# ========================


@app.route('/admin/reports')
def admin_reports():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. Total Students
        cursor.execute(
            "SELECT COUNT(*) as count FROM users WHERE role = 'student'")
        total_students = cursor.fetchone()['count']

        # 2. Total Organizations
        cursor.execute(
            "SELECT COUNT(*) as count FROM users WHERE role = 'organization'")
        total_orgs = cursor.fetchone()['count']

        # 3. Total Internship Postings (Since you don't have a 'slots' column)
        cursor.execute("SELECT COUNT(*) as total FROM internships")
        total_slots = cursor.fetchone()['total']

        # 4. Total Successful Placements
        cursor.execute(
            "SELECT COUNT(*) as count FROM applications WHERE status = 'accepted'")
        placements = cursor.fetchone()['count']

    except Exception as e:
        print(f"Error: {e}")
        total_students = total_orgs = total_slots = placements = 0

    finally:
        cursor.close()
        conn.close()

    return render_template('admin_reports.html',
                           students=total_students,
                           orgs=total_orgs,
                           slots=total_slots,
                           placements=placements)


# ========================
# ADMIN: VIEW ALL APPLICATIONS
# ========================
@app.route('/admin/all_applications')
@admin_required
def admin_all_applications():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT 
            a.id,
            u.full_name AS student_name,
            u.email AS student_email,
            i.title AS internship_title,
            org.full_name AS organization_name,
            a.status,
            DATE_FORMAT(a.created_at, '%Y-%m-%d') AS applied_at
        FROM applications a
        JOIN users u ON a.user_id = u.id
        JOIN internships i ON a.internship_id = i.id
        LEFT JOIN users org ON i.organization_id = org.id
        ORDER BY a.created_at DESC
    """

    try:
        cursor.execute(query)
        applications = cursor.fetchall()
    except Exception as e:
        print(f"--- [CRITICAL SQL ERROR IN ALL APPLICATIONS] ---")
        print(f"Details: {str(e)}")
        applications = []
    finally:
        cursor.close()
        conn.close()

    return render_template('admin_all_applications.html', applications=applications)


# ========================
# ADMIN: ACTIVE PLACEMENTS
# ========================
@app.route('/admin/placements')
@admin_required
def admin_placements():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT 
            p.id AS placement_id,
            u.full_name AS student_name,
            u.email AS student_email,
            i.title AS internship_title,
            org.full_name AS organization_name,
            p.status AS placement_status,
            DATE_FORMAT(p.created_at, '%Y-%m-%d') AS placed_at
        FROM placements p
        JOIN users u ON p.student_id = u.id
        JOIN internships i ON p.internship_id = i.id
        LEFT JOIN users org ON i.organization_id = org.id
        ORDER BY p.created_at DESC
    """
    try:
        cursor.execute(query)
        placements = cursor.fetchall()
    except Exception as e:
        print(f"--- [SQL ERROR IN PLACEMENTS MODULE] ---")
        print(f"Details: {str(e)}")
        placements = []
    finally:
        cursor.close()
        conn.close()

    return render_template('admin_placements.html', placements=placements)


@app.route('/admin/all_evaluations')
@admin_required
def admin_all_evaluations():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Grabs evaluation submissions linking students, supervisors, and organizations
    query = """
        SELECT 
            e.id AS evaluation_id,
            u.full_name AS student_name,
            sup.full_name AS supervisor_name,
            org.full_name AS organization_name,
            e.grade,
            e.comments,
            DATE_FORMAT(e.created_at, '%Y-%m-%d') AS evaluated_at
        FROM evaluations e
        JOIN placements p ON e.placement_id = p.id
        JOIN users u ON p.student_id = u.id
        LEFT JOIN users sup ON p.supervisor_id = sup.id
        LEFT JOIN internships i ON p.internship_id = i.id
        LEFT JOIN users org ON i.organization_id = org.id
        ORDER BY e.created_at DESC
    """

    try:
        cursor.execute(query)
        evaluations = cursor.fetchall()
    except Exception as e:
        print(f"--- [SQL ERROR IN EVALUATIONS MODULE] ---")
        print(f"Details: {str(e)}")
        evaluations = []
    finally:
        cursor.close()
        conn.close()

    return render_template('admin_evaluations.html', evaluations=evaluations)


@app.route('/evaluation/<int:eval_id>')
@login_required
def shared_evaluation_details(eval_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT
            e.*,
            u.full_name AS student_name,
            i.title,
            org.full_name AS org_name,
            sup.full_name AS supervisor_name
        FROM evaluations e
        JOIN placements p ON e.placement_id = p.id
        JOIN users u ON p.student_id = u.id
        LEFT JOIN internships i ON p.internship_id = i.id
        LEFT JOIN users org ON i.organization_id = org.id
        LEFT JOIN users sup ON p.supervisor_id = sup.id
        WHERE e.id = %s
    """

    cursor.execute(query, (eval_id,))
    evaluation = cursor.fetchone()

    cursor.close()
    conn.close()

    if not evaluation:
        return "Evaluation not found", 404

    return render_template('view_evaluation.html', eval=evaluation)

# ========================
# ADMIN: PROCESS APPLICATIONS
# ========================


@app.route('/admin/application/<int:app_id>/<action>', methods=['POST'])
@admin_required
def admin_process_application(app_id, action):
    if action not in ['accept', 'reject']:
        return redirect(url_for('admin_all_applications'))

    status = 'accepted' if action == 'accept' else 'rejected'
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "UPDATE applications SET status = %s WHERE id = %s", (status, app_id))
        conn.commit()
    except Exception as e:
        print(f"Admin application processing error: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_all_applications'))


# ========================
# ORGANIZATION VERIFY INTERNS
# ========================
@app.route('/organization/application/<int:app_id>/handle/<string:new_status>')
def manage_application_decision(app_id, new_status):
    user_id = session.get('user_id')
    role = session.get('role')

    # 1. Access Control Security Guard
    if not user_id:
        flash("Your session has expired. Please log in again.", "warning")
        return redirect(url_for('login'))

    if role != 'organization' and role != 'employer':
        flash("Unauthorized access attempt detected.", "error")
        return redirect(url_for('dashboard'))

    # Map validation to match your exact database ENUM structure ('approved' or 'rejected')
    status_lower = str(new_status).strip().lower()
    if 'accept' in status_lower or status_lower == 'approved':
        db_status = 'approved'
    elif 'reject' in status_lower or status_lower == 'rejected':
        db_status = 'rejected'
    else:
        flash("Invalid status decision parameter.", "error")
        return redirect(url_for('view_applicants'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 2. Fetch the specific organization primary key ID mapped to this logged-in user
        cursor.execute(
            "SELECT id FROM organizations WHERE user_id = %s", (user_id,))
        org_row = cursor.fetchone()
        db_org_id = org_row['id'] if org_row else None

        # 3. Update the application status using valid ENUM text and update organization_id
        cursor.execute("""
            UPDATE applications 
            SET status = %s, 
                organization_id = COALESCE(organization_id, %s)
            WHERE id = %s
        """, (db_status, db_org_id, app_id))
        conn.commit()

        # Display clean casing in logs/flash messaging
        display_status = db_status.capitalize()
        print(
            f"====> ✅ SUCCESS: Application ID {app_id} marked as {db_status} <====")
        flash(
            f"Application status updated to {display_status} successfully!", "success")

        # 4. Dynamic Action Logging integration
        try:
            log_action(
                f"Updated Application {app_id} to {display_status}", user_id)
        except NameError:
            pass

    except Exception as e:
        print(f"❌ CRITICAL ERROR UPDATING APPLICATION STATUS: {e}")
        try:
            conn.rollback()
        except:
            pass
        flash("Failed to update status due to a database system error.", "error")

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    # 5. Redirect cleanly back to the applicants workspace stream view function area
    return redirect(url_for('view_applicants'))
# =========================
# ADMIN: VIEW STUDENT PROFILE
# =========================


@app.route('/admin/view-student/<int:student_id>')
def view_student(student_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch details for the specific student based on their ID
    cursor.execute(
        "SELECT * FROM users WHERE id = %s AND role = 'student'", (student_id,))
    student = cursor.fetchone()

    cursor.close()
    conn.close()

    if student:
        return render_template('admin_view_student.html', student=student)
    else:
        return "Student not found in database", 404

# =========================
# ADMIN ALLOCATIONS
# =========================


@app.route('/admin/allocations', methods=['GET', 'POST'])
def admin_allocations():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        action = request.form.get('action')

        # Handle Deletion
        if action == 'delete':
            allocation_id = request.form.get('allocation_id')
            try:
                cursor.execute(
                    "DELETE FROM allocations WHERE id = %s", (allocation_id,))
                conn.commit()
                flash("Allocation removed successfully.", "success")
            except Exception as e:
                print(f"❌ ALLOCATION DELETE ERROR: {e}")
                conn.rollback()
                flash("Failed to delete the allocation record.", "danger")
            finally:
                cursor.close()
                conn.close()
            return redirect(url_for('admin_allocations'))

        # Handle Assignment / Update
        raw_student_id = request.form.get('student_id')
        # Correctly targeted supervisor element
        supervisor_id = request.form.get('supervisor_id')

        if not raw_student_id or not supervisor_id:
            flash(
                "Please choose valid options for both student and supervisor.", "warning")
            cursor.close()
            conn.close()
            return redirect(url_for('admin_allocations'))

        try:
            # 🔍 Resolve true primary key ID from the students table mapping layer
            cursor.execute(
                "SELECT id FROM students WHERE id = %s OR user_id = %s",
                (raw_student_id, raw_student_id)
            )
            student_record = cursor.fetchone()

            if student_record:
                student_id = student_record['id']
            else:
                cursor.execute(
                    "INSERT INTO students (user_id) VALUES (%s)", (raw_student_id,))
                conn.commit()
                student_id = cursor.lastrowid

            # 🔍 Scan assignments using 'student_id'
            cursor.execute(
                "SELECT id FROM allocations WHERE student_id = %s", (student_id,))
            existing_allocation = cursor.fetchone()

            if existing_allocation:
                # Update the supervisor_id mapping safely
                cursor.execute(
                    "UPDATE allocations SET supervisor_id = %s WHERE student_id = %s",
                    (supervisor_id, student_id)
                )
                flash("Supervisor assignment updated successfully!", "success")
            else:
                # Insert pristine assignment pairing
                cursor.execute(
                    "INSERT INTO allocations (student_id, supervisor_id) VALUES (%s, %s)",
                    (student_id, supervisor_id)
                )
                flash("Supervisor allocated successfully!", "success")

            conn.commit()
        except Exception as e:
            print(f"❌ ALLOCATION SYSTEM POST ERROR: {e}")
            conn.rollback()
            flash(
                "A database constraint error occurred. Make sure employer_id is nullable.", "danger")
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('admin_allocations'))

    # --- GET REQUEST FLOW HANDLING ---
    students = []
    supervisors = []
    current_assignments = []

    try:
        # Fetch Students matching their specific user roles
        cursor.execute(
            "SELECT id, full_name FROM users WHERE role = 'student'")
        students = cursor.fetchall()

        # 🔍 RESTORED: Pull actual supervisors directly from the users repository
        cursor.execute(
            "SELECT id, full_name FROM users WHERE role = 'supervisor'")
        supervisors = cursor.fetchall()

        # 🔍 RESTORED: Build relational link straight from allocations back to supervisor user profile
        query = """
            SELECT 
                a.id, 
                u_student.full_name AS student_name, 
                u_supervisor.full_name AS supervisor_name 
            FROM allocations a
            JOIN students s ON a.student_id = s.id
            JOIN users u_student ON s.user_id = u_student.id
            JOIN users u_supervisor ON a.supervisor_id = u_supervisor.id
        """
        cursor.execute(query)
        current_assignments = cursor.fetchall()

    except Exception as e:
        print(f"❌ ALLOCATION SYSTEM GET ERROR: {e}")
        flash("System failed to load current allocation matrices.", "danger")
    finally:
        cursor.close()
        conn.close()

    return render_template('admin_allocations.html',
                           students=students,
                           supervisors=supervisors,
                           assignments=current_assignments)


# ==========================
# ORGANIZATION APPLICATION
# ==========================
@app.route('/organization/applications')
def organization_applications():
    # ... your database logic to get applications ...
    return render_template('organization_dashboard.html',
                           applications=applications,
                           active_module='applications')


# =========================
# CURRENT INTENS
# ==========================


@app.route('/organization/interns')
def current_interns():
    user_id = session.get('user_id')
    role = session.get('role')

    # 1. Access Control Guard
    if not user_id:
        flash("Your session has expired. Please log in again.", "warning")
        return redirect(url_for('login'))

    if role != 'organization' and role != 'employer':
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    interns = []

    try:
        # 2. Get the specific organization primary key ID mapped to this logged-in user
        cursor.execute(
            "SELECT id FROM organizations WHERE user_id = %s", (user_id,))
        org_row = cursor.fetchone()

        if not org_row:
            return render_template('current_interns.html', interns=[])

        db_org_id = org_row['id']

        # 3. HIGHLY REFINED JOIN QUERY MATCHING phpMyAdmin COLUMNS
        # - Fixed: status changed to 'approved' to match your ENUM constraints perfectly.
        # - Fixed: Single '%' characters used for direct MySQL execution.
        query = """
            SELECT DISTINCT
                COALESCE(u.full_name, u2.full_name, 'Assigned Student') AS student_name,
                COALESCE(u.email, u2.email, 'N/A') AS student_email,
                i.title AS internship_role,
                a.id AS app_id,
                DATE_FORMAT(COALESCE(a.application_date, a.applied_at, a.created_at, NOW()), '%d/%m/%Y') AS start_date
            FROM applications a
            JOIN internships i ON a.internship_id = i.id
            LEFT JOIN users u ON (a.user_id = u.id OR a.student_id = u.id)
            LEFT JOIN students s ON a.student_id = s.id
            LEFT JOIN users u2 ON s.user_id = u2.id
            WHERE i.employer_id = %s 
              AND TRIM(LOWER(a.status)) = 'approved'
            ORDER BY a.id DESC
        """
        cursor.execute(query, (db_org_id,))
        interns = cursor.fetchall()

        print(
            f"====> ✅ INTERNS DASHBOARD SUCCESS: Found {len(interns)} active interns for Org ID {db_org_id} <====")

    except Exception as e:
        print(f"❌ CRITICAL DATABASE ERROR IN INTERNS MODULE: {e}")
        interns = []

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    # 🎯 Render the interface layout cleanly targeting your actual template filename
    return render_template('current_interns.html', interns=interns)


# Route to see the list of all evaluatable interns
@app.route('/organization/evaluations', endpoint='organization_evaluations')
def evaluations_list():
    org_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Changed i.company_id to i.user_id to match your database schema
        query = """
        SELECT 
            u.full_name, 
            i.title, 
            a.id as app_id 
        FROM applications a
        JOIN internships i ON a.internship_id = i.id
        JOIN users u ON a.user_id = u.id
        WHERE i.user_id = %s AND a.status = 'accepted'
        """
        cursor.execute(query, (org_id,))
        interns = cursor.fetchall()
    except Exception as e:
        print(f"Error in evaluations_list: {e}")
        interns = []
    finally:
        cursor.close()
        conn.close()

    return render_template('evaluations.html', interns=interns)

# Route for the specific evaluation form


@app.route('/organization/evaluate/<int:app_id>')
def evaluate_student(app_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch student details to show on the form
    query = "SELECT u.full_name, i.title FROM applications a JOIN internships i ON a.internship_id = i.id JOIN users u ON a.user_id = u.id WHERE a.id = %s"
    cursor.execute(query, (app_id,))
    student = cursor.fetchone()

    cursor.close()
    conn.close()
    return render_template('evaluation_form.html', student=student, app_id=app_id)

# ============================
# ADMIN ADD STUDENTS
# ===========================


@app.route('/admin/add_supervisor', methods=['GET', 'POST'])
@admin_required
def add_supervisor():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = "87770"  # Temporary default password
        hashed_pw = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # We insert into 'users' but set the role to 'supervisor'
            cursor.execute(
                "INSERT INTO users (full_name, email, password, role) VALUES (%s, %s, %s, 'supervisor')",
                (full_name, email, hashed_pw)
            )
            conn.commit()
            log_action(f"Created Supervisor: {email}", session.get('email'))
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            return f"Error: {e}"
        finally:
            cursor.close()
            conn.close()

    return render_template('admin_add_supervisor.html')


@app.route('/admin/assign_supervisor', methods=['POST'])
@admin_required
def assign_supervisor():
    student_id = request.form.get('student_id')
    supervisor_id = request.form.get('supervisor_id')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # 1. Check if the student is already assigned
        cursor.execute(
            "SELECT id FROM allocations WHERE student_id = %s", (student_id,))
        if cursor.fetchone():
            # Update the existing assignment
            cursor.execute("UPDATE allocations SET supervisor_id = %s WHERE student_id = %s",
                           (supervisor_id, student_id))
        else:
            # Create a brand new assignment
            cursor.execute("INSERT INTO allocations (student_id, supervisor_id) VALUES (%s, %s)",
                           (student_id, supervisor_id))

        conn.commit()
        log_action(
            f"Assigned Student {student_id} to Supervisor {supervisor_id}", session.get('email'))

    except Exception as e:
        print(f"Assignment Error: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_dashboard'))


# =========================
# ADMIN ANALYTICS
# ========================
@app.route('/admin/analytics')
@admin_required
def admin_analytics():
    conn = None
    status_data = []
    org_data = []

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Application Status Distribution
        cursor.execute(
            "SELECT status, COUNT(*) as count FROM applications GROUP BY status")
        status_data = cursor.fetchall()

        # 2. Students per Organization (Fixed Column Name)
        # Check your DB: if it's not company_id, it might be org_id
        query = """
            SELECT u.full_name as org_name, COUNT(a.id) as student_count 
            FROM applications a 
            JOIN users u ON a.company_id = u.id 
            WHERE a.status = 'accepted'
            GROUP BY u.full_name
        """
        cursor.execute(query)
        org_data = cursor.fetchall()

        cursor.close()
    except Exception as e:
        print(f"Analytics Error: {e}")
        # If the error persists, it's likely the column name.
        # Check if your table uses 'org_id' instead of 'company_id'
    finally:
        if conn and conn.is_connected():
            conn.close()

    return render_template('admin_analytics.html',
                           status_data=status_data,
                           org_data=org_data)


# =========================
# RUN APP
# =========================
if __name__ == '__main__':
    app.run(debug=True)
