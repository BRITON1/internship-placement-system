from flask import Flask, render_template, request, redirect, url_for, session
from database.db_connection import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import timedelta
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
    if request.method == 'GET':
        if session.get('user_id'):
            dashboards = {
                'student': 'student_dashboard',
                'organization': 'organization_dashboard',
                'supervisor': 'supervisor_dashboard',
                'admin': 'admin_dashboard'
            }
            return redirect(url_for(dashboards.get(session.get('role', ''), 'login')))
        return render_template('login.html')

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
            session.clear()
            session['user_id'] = user['id']
            session['full_name'] = user['full_name']
            session['role'] = user['role']
            session['email'] = user['email']
            session.permanent = True

            dashboards = {
                'student': 'student_dashboard',
                'organization': 'organization_dashboard',
                'supervisor': 'supervisor_dashboard',
                'admin': 'admin_dashboard'
            }
            return redirect(url_for(dashboards.get(user['role'], 'login')))

        return render_template('login.html', error="Invalid email or password ❌")

    except Exception as e:
        print(f"Login System Error: {e}")
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
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # 1. SECURITY: Only allow these roles via public registration
        if role not in ['student', 'organization']:
            return "Unauthorized role selection. ⛔", 403

        # 2. HASHING: Never store plain text!
        hashed_pw = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            query = "INSERT INTO users (full_name, email, password, role) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (full_name, email, hashed_pw, role))
            conn.commit()
            log_action("User Registered", email)
            return redirect(url_for('login'))
        except Exception as e:
            return f"An error occurred: {e}"
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

    # 1. Get Open Slots (Total capacity across all posts by this org)
    cursor.execute(
        "SELECT SUM(slots) as total FROM internships WHERE organization_id = %s", (user_id,))
    result = cursor.fetchone()
    open_slots = result['total'] if result['total'] else 0

    # 2. Get Pending Applications (Count students waiting for a response)
    cursor.execute("""
        SELECT COUNT(*) as total FROM applications a
        JOIN internships i ON a.internship_id = i.id
        WHERE i.organization_id = %s AND a.status = 'pending'
    """, (user_id,))
    pending_apps = cursor.fetchone()['total']

    # 3. Get Active Interns (Count students already accepted)
    cursor.execute("""
        SELECT COUNT(*) as total FROM applications a
        JOIN internships i ON a.internship_id = i.id
        WHERE i.organization_id = %s AND a.status = 'accepted'
    """, (user_id,))
    active_interns = cursor.fetchone()['total']

    # 4. Get Company Name for Initials
    cursor.execute("SELECT full_name FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    initial = user['full_name'][0].upper() if user else "T"

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

    # We JOIN the allocations table with the users table to get Student Details
    query = """
        SELECT 
            u.id, 
            u.full_name, 
            u.email,
            u.role
        FROM allocations a
        JOIN users u ON a.student_id = u.id
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

# =========================
# LOGBOOK: STUDENT SUBMISSION
# =========================


# =========================
# LOGBOOK: SUPERVISOR VIEW & APPROVE
# =========================


@app.route('/supervisor/logbooks')
def view_student_logs():
    supervisor_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch all logs from students assigned to THIS supervisor
    query = """
        SELECT l.*, u.full_name as student_name 
        FROM logbooks l
        JOIN users u ON l.student_id = u.id
        WHERE l.supervisor_id = %s
        ORDER BY l.activity_date DESC
    """
    cursor.execute(query, (supervisor_id,))
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
            SELECT a.*, u.full_name as student_name, a.created_at as assessment_date 
            FROM assessments a
            JOIN users u ON a.student_id = u.id
            WHERE a.supervisor_id = %s
            ORDER BY a.created_at DESC
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

# 2. SUBMIT NEW ASSESSMENT


@app.route('/supervisor/assessment/new', methods=['GET', 'POST'])
@login_required
def new_assessment():
    supervisor_id = session.get('user_id')
    if session.get('role') != 'supervisor':
        return "Access Denied", 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        try:
            # 1. Capture data from the HTML form (Check your <input name="...">)
            student_id = request.form.get('student_id')
            attendance = request.form.get('attendance')
            skills = request.form.get('skills')
            attitude = request.form.get('attitude')
            overall = request.form.get('overall')
            comments = request.form.get('comments')

            # 2. SQL Insert
            # IMPORTANT: Ensure your DB table has these exact column names
            query = """
                INSERT INTO assessments 
                (student_id, supervisor_id, attendance_score, skills_score, attitude_score, overall_score, comments, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """

            cursor.execute(query, (
                student_id,
                supervisor_id,
                attendance,
                skills,
                attitude,
                overall,
                comments
            ))
            conn.commit()

            # Optional: Log action if you have this function
            try:
                log_action(
                    f"Submitted Assessment for Student ID {student_id}", session.get('email'))
            except:
                pass

            return redirect(url_for('view_assessments'))

        except Exception as e:
            print(f"Error saving assessment: {e}")
            conn.rollback()
            return f"Error saving assessment: {e}", 500
        finally:
            cursor.close()
            conn.close()

    # --- GET Method ---
    try:
        # Fetch only students assigned to this supervisor via the allocations table
        cursor.execute("""
            SELECT u.id, u.full_name 
            FROM allocations a
            JOIN users u ON a.student_id = u.id
            WHERE a.supervisor_id = %s
        """, (supervisor_id,))
        assigned_students = cursor.fetchall()

        return render_template('new_assessment.html', students=assigned_students)
    except Exception as e:
        print(f"Error fetching students: {e}")
        return "Error loading students", 500
    finally:
        # Only close if they haven't been closed by a previous block
        try:
            cursor.close()
            conn.close()
        except:
            pass


@app.route('/supervisor/assessment/view/<int:assessment_id>')
@login_required
def view_assessment_detail(assessment_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch the specific assessment details and the student's name
    query = """
        SELECT a.*, u.full_name as student_name 
        FROM assessments a
        JOIN users u ON a.student_id = u.id
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
@login_required
def manage_slots():
    user_id = session.get('user_id')
    company = session.get('company_name', 'Organization')

    if not user_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # --- CHECK VERIFICATION STATUS ---
    try:
        cursor.execute(
            "SELECT is_verified FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user or not user.get('is_verified'):
            cursor.close()
            conn.close()
            return "Your account is pending admin verification. You cannot post yet.", 403

    except Exception as e:
        print(f"Verification check error: {e}")
        cursor.close()
        conn.close()
        return "Something went wrong. Try again.", 500

    # --- PART 1: HANDLE FORM SUBMISSION ---
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            description = request.form.get('description')
            category = request.form.get('category')
            location = request.form.get('location')
            slots = request.form.get('available_slots')
            duration = request.form.get('duration')
            requirements = request.form.get('requirements')
            start_date = request.form.get('start_date')
            deadline = request.form.get('end_date')

            query = """
                INSERT INTO internships 
                (user_id, organization_id, title, description, category, location, 
                 slots, duration, requirements, start_date, deadline, status, created_at) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'open', NOW())
            """

            values = (
                user_id, user_id, title, description, category, location,
                slots, duration, requirements, start_date, deadline
            )

            cursor.execute(query, values)
            conn.commit()

            print("✅ Internship posted successfully!")
            return redirect(url_for('manage_slots'))

        except Exception as e:
            print(f"Error saving internship: {e}")
            conn.rollback()

    # --- PART 2: FETCH INTERNSHIPS (GET) ---
    try:
        query = """
            SELECT * FROM internships 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        """
        cursor.execute(query, (user_id,))
        slots = cursor.fetchall()

    except Exception as e:
        print(f"SQL Error: {e}")
        slots = []

    initial = company[0].upper() if company else "T"

    cursor.close()
    conn.close()

    return render_template(
        'manage_slots.html',
        slots=slots,
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
def view_internship():
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1. Fetch all internships
    cursor.execute("SELECT * FROM internships")
    internships = cursor.fetchall()

    # 2. Fetch IDs of internships this student has already applied for
    cursor.execute(
        "SELECT internship_id FROM applications WHERE student_id = %s", (user_id,))
    applied_ids = [row['internship_id'] for row in cursor.fetchall()]

    cursor.close()
    conn.close()

    return render_template('student_dashboard.html',
                           internships=internships,
                           applied_ids=applied_ids)
# =========================
# STUDENT: APPLY FOR INTERNSHIP
# =========================


@app.route('/apply', methods=['POST'])
def apply():
    # Let's call it user_id to match the session and the FK
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    internship_id = request.form.get('internship_id')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. CHECK DUPLICATE (Using user_id to be safe)
        check_query = "SELECT * FROM applications WHERE user_id=%s AND internship_id=%s"
        cursor.execute(check_query, (user_id, internship_id))
        existing = cursor.fetchone()

        if existing:
            return "You have already applied for this position! ⚠️"

        # 2. INSERT - CRITICAL FIX HERE
        # We are inserting the session ID into BOTH user_id and student_id
        # so that all your different route queries can find the data.
        insert_query = """
        INSERT INTO applications (user_id, student_id, internship_id, status)
        VALUES (%s, %s, %s, 'pending')
        """
        cursor.execute(insert_query, (user_id, user_id, internship_id))
        conn.commit()

        # 3. LOG ACTION
        log_action("Applied for Internship", user_id)

    except Exception as e:
        # If MySQL rejects the insert, it will print to your terminal now!
        print(f"DATABASE ERROR IN APPLY ROUTE: {e}")
        conn.rollback()  # Undo the failed transaction
        return f"Database Error: Could not process application. Check terminal."

    finally:
        cursor.close()
        conn.close()

    # 4. REDIRECT
    return redirect(url_for('student_applications'))


# =========================
# ORGANIZATION: VIEW APPLICANTS
# =========================

@app.route('/organization/applicants')
def view_applicants():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
    SELECT 
        applications.id,
        users.full_name,
        users.email,
        internships.title,
        applications.status
    FROM applications
    JOIN users ON applications.user_id = users.id
    JOIN internships ON applications.internship_id = internships.id
    """

    cursor.execute(query)
    applications = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('view_applicants.html', applications=applications)


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
@login_required
@admin_required
def verify_organization(org_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    verified = False
    try:
        cursor.execute("DESCRIBE users")
        columns = [row[0] for row in cursor.fetchall()]

        if 'verification_status' in columns:
            try:
                cursor.execute(
                    "UPDATE users SET verification_status = 'Verified' WHERE id = %s", (org_id,))
                verified = True
            except mysql.connector.Error as e:
                print(f"Could not update verification_status: {e}")

        if 'is_verified' in columns:
            try:
                cursor.execute(
                    "UPDATE users SET is_verified = TRUE WHERE id = %s", (org_id,))
                verified = True
            except mysql.connector.Error as e:
                print(f"Could not update is_verified: {e}")

        if verified:
            conn.commit()
        else:
            print(f"No verification column found for organization {org_id}")
    except Exception as e:
        print(f"Error verifying organization {org_id}: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_organizations'))
# ========================
# ADMIN: ORGANIZATIONS
# ========================


@app.route('/admin/organizations')
@login_required
def admin_organizations():
    if session.get('role') != 'admin':
        return "Access Denied", 403

    conn = get_db_connection()
    # Keep dictionary=True so we can use org.full_name in HTML
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch all users who are organizations
        # Make sure is_verified is in your SELECT
        query = "SELECT id, full_name, email, is_verified FROM users WHERE role = 'organization'"
        cursor.execute(query)
        organizations = cursor.fetchall()

        return render_template('admin_organizations.html', organizations=organizations)

    except Exception as e:
        print(f"Error: {e}")
        return f"Database Error: {e}", 500
    finally:
        cursor.close()
        conn.close()

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
            "SELECT COUNT(*) AS count FROM users WHERE role='organization'")
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
        LEFT JOIN users u ON i.user_id = u.id
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
# CURRENT INTERNS
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
# ADMIN VIEW STUDENTS
# ========================
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
        student_id = request.form.get('student_id')
        supervisor_id = request.form.get('supervisor_id')

        # Save the assignment to the database
        cursor.execute("INSERT INTO allocations (student_id, supervisor_id) VALUES (%s, %s)",
                       (student_id, supervisor_id))
        conn.commit()
        return redirect(url_for('admin_allocations'))

    # Fetch Students for dropdown
    cursor.execute("SELECT id, full_name FROM users WHERE role = 'student'")
    students = cursor.fetchall()

    # Fetch Supervisors for dropdown
    cursor.execute("SELECT id, full_name FROM users WHERE role = 'supervisor'")
    supervisors = cursor.fetchall()

    # Fetch Current Assignments for the table
    query = """
        SELECT 
            a.id, 
            s.full_name AS student_name, 
            v.full_name AS supervisor_name 
        FROM allocations a
        JOIN users s ON a.student_id = s.id
        JOIN users v ON a.supervisor_id = v.id
    """
    cursor.execute(query)
    current_assignments = cursor.fetchall()

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
    # Force a login check for debugging
    org_id = session.get('user_id')
    if not org_id:
        return "Session Error: No user_id found. Please log in again."

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # We use a broad query first to make sure WE FIND SOMETHING
        # If this works, we narrow it down to company_id later
        query = """
        SELECT 
            u.full_name AS student_name,
            u.email AS student_email,
            i.title AS internship_role,
            a.id AS app_id,
            DATE_FORMAT(a.created_at, '%%d/%%m/%%Y') AS start_date
        FROM applications a
        JOIN internships i ON a.internship_id = i.id
        LEFT JOIN users u ON a.user_id = u.id
        WHERE a.status = 'accepted'
        """
        cursor.execute(query)
        interns = cursor.fetchall()

        print(
            f"DEBUG SUCCESS: Found {len(interns)} total accepted interns in system.")

    except Exception as e:
        print(f"SQL ERROR: {e}")
        interns = []
    finally:
        cursor.close()
        conn.close()

    return render_template('current_interns.html', interns=interns)


# Route to see the list of all evaluatable interns
@app.route('/organization/evaluations')
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
