# ... (previous imports)

# Database setup
def init_db():
    conn = sqlite3.connect('otp_auth.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 phone_number TEXT UNIQUE NOT NULL,
                 status TEXT DEFAULT 'new',
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create tokens table
    c.execute('''CREATE TABLE IF NOT EXISTS tokens (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER NOT NULL,
                 access_token TEXT,
                 refresh_token TEXT,
                 access_token_expire_at INTEGER,
                 refresh_token_expire_at INTEGER,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    # Create otp_requests table
    c.execute('''CREATE TABLE IF NOT EXISTS otp_requests (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER NOT NULL,
                 otp_code TEXT,
                 status TEXT,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    conn.commit()
    conn.close()

# Database migration handler
def migrate_db():
    conn = sqlite3.connect('otp_auth.db')
    c = conn.cursor()
    
    try:
        # Check if admins table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admins'")
        admin_table_exists = c.fetchone() is not None
        
        if not admin_table_exists:
            logger.info("Creating admins table...")
            c.execute('''CREATE TABLE admins (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         username TEXT UNIQUE NOT NULL,
                         password_hash TEXT NOT NULL,
                         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # Future migrations can be added here
        # Example:
        # c.execute("SELECT * FROM pragma_table_info('admins') WHERE name='new_column'")
        # if not c.fetchone():
        #     c.execute("ALTER TABLE admins ADD COLUMN new_column TEXT")
    
    except Exception as e:
        logger.error(f"Database migration failed: {str(e)}")
    finally:
        conn.commit()
        conn.close()

# Initialize the database
init_db()
migrate_db()  # Run migrations after initial setup

# ... (rest of the code)