from flask import Flask, render_template, request, redirect, url_for
from database.db_connection import get_db_connection
import mysql.connector
# UPDATE THIS LINE AT THE TOP OF app.py
from flask import Flask, render_template, request, redirect, url_for, session

# Also ensure you have a secret key set, or sessions won't work!
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # You need this line!


# =========================
# AUDIT LOG FUNCTION
# =========================
def log_action(action, user_email):
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "INSERT INTO audit_logs (action, user_email) VALUES (%s, %s)"
    cursor.execute(query, (action, user_email))
    conn.commit()

    cursor.close()
    conn.close()


# =========================
# HOME
# =========================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get('email')
    password = request.form.get('password')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    query = "SELECT * FROM users WHERE email=%s AND password=%s"
    cursor.execute(query, (email, password))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user:
        session['user_id'] = user['id']
        session['full_name'] = user['full_name']
        session['email'] = user['email']

        role = user['role']
        if role == 'student':
            return redirect(url_for('student_dashboard'))
        if role == 'organization':
            return redirect(url_for('organization_dashboard'))
        if role == 'supervisor':
            return redirect(url_for('supervisor_dashboard'))
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))

    return "Invalid credentials ❌"
# =========================
# AUTH (REGISTER + LOGIN)
# =========================


@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register():
    full_name = request.form.get('full_name')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')

    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
    INSERT INTO users (full_name, email, password, role)
    VALUES (%s, %s, %s, %s)
    """

    try:
        cursor.execute(query, (full_name, email, password, role))
        conn.commit()

        # ✅ LOG ACTION
        log_action("User Registered", email)

        return redirect(url_for('login_page'))

    except mysql.connector.errors.IntegrityError:
        return "Email already exists 🤷‍♂️"

    finally:
        cursor.close()
        conn.close()


# ========================
# LOGIN
# ========================


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

    # 1. Fetch student's logbook history
    cursor.execute("""
        SELECT activity_date, week_number, status, supervisor_comment
        FROM logbooks
        WHERE student_id = %s
        ORDER BY activity_date DESC
    """, (user_id,))
    logs = cursor.fetchall()

    # 2. Get student name for avatar
    cursor.execute("SELECT full_name FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    initial = user['full_name'][0].upper() if user else "K"

    # 3. Fetch Application Stats for the Dashboard Cards
    cursor.execute(
        "SELECT COUNT(*) as total FROM applications WHERE student_id = %s", (user_id,))
    app_count = cursor.fetchone()['total']

    # You can add more specific counts here later (Accepted/Rejected)
    # cursor.execute("SELECT COUNT(*) as accepted FROM applications WHERE student_id = %s AND status='accepted'", (user_id,))

    cursor.close()
    conn.close()

    return render_template('student_dashboard.html',
                           logs=logs,
                           initial=initial,
                           app_count=app_count)

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
    # Example values - replace with your actual database query results
    open_slots = 1
    pending_apps = 1
    active_interns = 0
    company_name = "Tech Corp"  # Get from session

    # Generate initials for the display picture
    initial = company_name[0].upper() if company_name else "T"

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
def supervisor_dashboard():
    supervisor_id = session.get('user_id')
    if not supervisor_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Count Assigned Students
    cursor.execute(
        "SELECT COUNT(*) AS count FROM allocations WHERE supervisor_id = %s", (supervisor_id,))
    assigned_count = cursor.fetchone()['count']

    # Get supervisor name for the initial avatar
    cursor.execute("SELECT full_name FROM users WHERE id = %s",
                   (supervisor_id,))
    user = cursor.fetchone()
    initial = user['full_name'][0].upper() if user else "S"

    cursor.close()
    conn.close()

    return render_template('supervisor_dashboard.html',
                           assigned_count=assigned_count,
                           pending_reviews=0,
                           submitted_grades=0,
                           initial=initial)

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


@app.route('/supervisor/logbook/approve/<int:log_id>', methods=['POST'])
def approve_log(log_id):
    comment = request.form.get('comment')
    status = request.form.get('status')  # 'approved' or 'revision_requested'

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE logbooks SET status=%s, supervisor_comment=%s WHERE id=%s",
                   (status, comment, log_id))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('view_student_logs'))


@app.route('/supervisor/assessments')
def view_assessments():
    supervisor_id = session.get('user_id')
    if not supervisor_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Join with users to get student names
    query = """
        SELECT a.*, u.full_name as student_name 
        FROM assessments a
        JOIN users u ON a.student_id = u.id
        WHERE a.supervisor_id = %s
        ORDER BY a.assessment_date DESC
    """
    cursor.execute(query, (supervisor_id,))
    assessments = cursor.fetchall()

    # Get initial for avatar
    cursor.execute("SELECT full_name FROM users WHERE id = %s",
                   (supervisor_id,))
    user = cursor.fetchone()
    initial = user['full_name'][0].upper() if user else "S"

    cursor.close()
    conn.close()
    return render_template('supervisor_assessments.html', assessments=assessments, initial=initial)
# ===========================
# NEW ASSESSMENT
# ===========================


@app.route('/supervisor/assessment/new', methods=['GET', 'POST'])
def new_assessment():
    supervisor_id = session.get('user_id')
    if not supervisor_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        attendance = request.form.get('attendance')
        skills = request.form.get('skills')
        attitude = request.form.get('attitude')
        overall = request.form.get('overall')
        comments = request.form.get('comments')

        # Insert into the assessments table
        query = """
            INSERT INTO assessments (student_id, supervisor_id, attendance_score, skills_score, attitude_score, overall_score, comments)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (student_id, supervisor_id,
                       attendance, skills, attitude, overall, comments))
        conn.commit()

        log_action(
            f"Submitted Assessment for Student ID {student_id}", session.get('email'))

        cursor.close()
        conn.close()
        return redirect(url_for('view_assessments'))

    # If GET, fetch the list of assigned students to populate the dropdown
    cursor.execute("""
        SELECT u.id, u.full_name, u.email 
        FROM allocations a
        JOIN users u ON a.student_id = u.id
        WHERE a.supervisor_id = %s
    """, (supervisor_id,))
    students = cursor.fetchall()

    cursor.close()
    conn.close()
    return render_template('new_assessment.html', students=students)


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


@app.route('/organization/post')
def manage_slots():
    # Get identifying info from session
    user_id = session.get('user_id')
    company = session.get('company_name', 'Organization')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check your database! If the column isn't 'company_name',
        # change it to 'organization' or 'user_id' below
        query = "SELECT * FROM internships WHERE company_name = %s"
        cursor.execute(query, (company,))
        slots = cursor.fetchall()
    except Exception as e:
        print(f"SQL Error: {e}")
        # If the query fails, we show an empty list instead of a 500 error
        slots = []

    initial = company[0].upper() if company else "T"

    cursor.close()
    conn.close()
    return render_template('manage_slots.html', slots=slots, initial=initial)


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
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetching open internships as you already defined
    cursor.execute("SELECT * FROM internships WHERE status='open'")
    internships = cursor.fetchall()

    cursor.close()
    conn.close()

    # CHANGE THIS: Point it to student_dashboard.html so the sidebar stays visible
    # Also ensure you pass 'initial' so the top-right avatar doesn't break
    return render_template('student_dashboard.html',
                           internships=internships,
                           initial='K')  # Replace 'K' with actual user initial logic

# =========================
# STUDENT: APPLY FOR INTERNSHIP
# =========================


@app.route('/apply', methods=['POST'])
def apply_internship():
    internship_id = request.form.get('internship_id')
    user_id = request.form.get('user_id')

    if not user_id:
        return "User not identified ❌"

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # CHECK DUPLICATE
    check_query = """
    SELECT * FROM applications 
    WHERE user_id=%s AND internship_id=%s
    """
    cursor.execute(check_query, (user_id, internship_id))
    existing = cursor.fetchone()

    if existing:
        cursor.close()
        conn.close()
        return "You already applied ⚠️"

    # INSERT
    insert_query = """
    INSERT INTO applications (user_id, internship_id, status)
    VALUES (%s, %s, 'pending')
    """
    cursor.execute(insert_query, (user_id, internship_id))
    conn.commit()

    # ✅ LOG ACTION
    log_action("Applied for Internship", user_id)

    cursor.close()
    conn.close()

    return redirect(url_for('view_internship'))


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
# ADMIN: ORGANIZATIONS
# ========================
@app.route('/admin/organizations')
def admin_organizations():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT id, full_name, email FROM users WHERE role='organization'")
    organizations = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin_organizations.html', organizations=organizations)


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
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS count FROM users WHERE role='student'")
    students = cursor.fetchone()['count']

    cursor.execute(
        "SELECT COUNT(*) AS count FROM users WHERE role='organization'")
    organizations = cursor.fetchone()['count']

    cursor.execute(
        "SELECT COUNT(*) AS count FROM applications WHERE status='accepted'")
    placed = cursor.fetchone()['count']

    cursor.execute(
        "SELECT COUNT(*) AS count FROM applications WHERE status='pending'")
    pending = cursor.fetchone()['count']

    cursor.close()
    conn.close()

    return render_template(
        'admin_dashboard.html',
        students=students,
        organizations=organizations,
        placed=placed,
        pending=pending
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
    # For simplicity, just redirect to home. In real app, you'd clear session/cookies.
    return redirect(url_for('index'))

# =========================
# STUDENT PROFILE
# =========================


@app.route('/student/profile')
def student_profile():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # In a real app, use session['email'] to get the current user
    cursor.execute(
        "SELECT full_name, email FROM users WHERE role='student' LIMIT 1")
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user:
        # Get the first letter of the name for the avatar
        initial = user['full_name'][0].upper() if user['full_name'] else "U"

        name_parts = user['full_name'].split(' ')
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else ""

        # Pass 'initial' to the template
        return render_template('student_profile.html',
                               user=user,
                               first_name=first_name,
                               last_name=last_name,
                               initial=initial)

    return "User not found", 404


# =========================
# STUDENT APPLICATIONS
# =========================
@app.route('/student/applications')
def student_applications():
    # Use session to make it real, or keep user_id = 1 for testing
    user_id = session.get('user_id', 1)

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # We JOIN internships to get the title/location
        # and JOIN users/companies to get the name of the organization
        query = """
        SELECT 
            a.status, 
            a.created_at AS date_applied,
            i.title, 
            i.location,
            u.full_name AS company_name
        FROM applications a
        JOIN internships i ON a.internship_id = i.id
        JOIN users u ON i.user_id = u.id
        WHERE a.user_id = %s
        ORDER BY a.created_at DESC
        """
        cursor.execute(query, (user_id,))
        applications = cursor.fetchall()
    except Exception as e:
        print(f"Database Error: {e}")
        applications = []

    # Get initial for the avatar
    cursor.execute("SELECT full_name FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    initial = user['full_name'][0].upper() if user else "S"

    cursor.close()
    conn.close()

    # CRITICAL: Point this to student_dashboard.html since that's where the code is!
    return render_template('student_dashboard.html', applications=applications, initial=initial)


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
# ADMIN VERIFY
# =========================


@app.route('/admin/verify-org/<int:org_id>', methods=['POST'])
def verify_organization(org_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Update the status to 'Verified'
    query = "UPDATE users SET verification_status = 'Verified' WHERE id = %s"
    cursor.execute(query, (org_id,))
    conn.commit()

    cursor.close()
    conn.close()
    return redirect(url_for('admin_organizations'))

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


# =========================
# RUN APP
# =========================
if __name__ == '__main__':
    app.run(debug=True)
