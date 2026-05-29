from werkzeug.security import generate_password_hash
from database.db_connection import get_db_connection

def create_admin():
    email = 'admin@internhub.com'
    password = '87771'
    hashed_pw = generate_password_hash(password)
    
    conn = get_db_connection()
    if not conn:
        print("Could not connect to database!")
        return

    try:
        cursor = conn.cursor()
        
        # 1. Find the old admin's user_id if they exist
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user:
            old_id = user[0] # If using standard cursor, it's a tuple
            # 2. Delete from child tables first to satisfy Foreign Keys
            cursor.execute("DELETE FROM admins WHERE user_id = %s", (old_id,))
            cursor.execute("DELETE FROM audit_logs WHERE user_id = %s", (old_id,))
            # 3. Now delete from parent table
            cursor.execute("DELETE FROM users WHERE id = %s", (old_id,))
        
        # 4. Insert the fresh Admin into users
        query = "INSERT INTO users (full_name, email, password, role) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, ('System Admin', email, hashed_pw, 'admin'))
        new_user_id = cursor.lastrowid
        
        # 5. Re-link in the admins table
        cursor.execute("INSERT INTO admins (user_id, department) VALUES (%s, %s)", 
                       (new_user_id, 'IT Department'))
        
        conn.commit()
        print(f"✅ SUCCESS: Admin '{email}' reset and re-linked.")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    create_admin()