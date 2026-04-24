from werkzeug.security import generate_password_hash
import mysql.connector


def reset_admin():
    # 1. Create a fresh hash for the password 'admin123'
    new_password = '87771'
    hashed_password = generate_password_hash(new_password)

    # 2. Database Connection (Update these if your MySQL settings are different)
    db_config = {
        'host': 'localhost',
        'user': 'root',      # Your MySQL username
        'password': '',      # Your MySQL password (leave empty if none)
        'database': 'internship_placement_system'  # Your database name
    }

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # 3. Check if the admin exists first
        # Change this if your admin email is different
        admin_email = 'admin@internhub.com'
        cursor.execute("SELECT id FROM users WHERE email = %s", (admin_email,))
        user = cursor.fetchone()

        if user:
            # Update the existing admin
            cursor.execute(
                "UPDATE users SET password = %s, role = 'admin' WHERE email = %s",
                (hashed_password, admin_email)
            )
            conn.commit()
            print(
                f"✅ SUCCESS: Admin '{admin_email}' updated. New password is: {new_password}")
        else:
            # Create the admin if it doesn't exist
            cursor.execute(
                "INSERT INTO users (full_name, email, password, role) VALUES (%s, %s, %s, %s)",
                ('System Admin', admin_email, hashed_password, 'admin')
            )
            conn.commit()
            print(
                f"✅ SUCCESS: Admin '{admin_email}' created. Password is: {new_password}")

    except Exception as e:
        print(f"❌ ERROR: {e}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()


if __name__ == "__main__":
    reset_admin()
