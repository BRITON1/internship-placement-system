import mysql.connector

def get_db_connection():
    try:
        # Professional MySQL connection for Workbench
        conn = mysql.connector.connect(
            host='localhost',
            user='root',         # Default MySQL user
            password='',         # Add your MySQL password if you set one
            port=3307,
            database='internship_placement_system', # Matches your setup
            charset='utf8mb4',
            collation='utf8mb4_general_ci'
        )
        return conn
    except Exception as e:
        print(f"CRITICAL: MySQL Connection Error: {e}")
        return None