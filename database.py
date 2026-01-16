import sqlite3
from security import hash_password , ph
def create_table():
    """
    Create a SQLite database table for storing usernames and hashed passwords.
    """
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username varchar2(159),
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()



def store_user(username, password):
    """ Store a new user with a hashed password in the database.    
    Args:
    username (str): The username to store.
    password (str): The password to hash and store.
    """
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    password_hash = hash_password(password)
    c.execute('INSERT OR REPLACE INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
    conn.commit()
    conn.close()

    

def verify_user(username,password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password_hash FROM users WHERE username = ?",(username,)
    )

    result = cursor.fetchone()
    conn.close()

    if result:  
        stored_password_hash = result[0]
        return ph.verify(stored_password_hash)  
    return False


def remove_user():
    username = input("Enter username to remove: ").strip()
    if username == "":
        print("Username cannot be empty.")
        return

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()

    conn.close()
    print(f"User '{username}' has been removed.")

def audit_table():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""create table if not exists audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    conn.commit()
    conn.close()


def log_event(username , action):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO audit_log (username , action) VALUES (? , ?)", (username , action))

    conn.commit()
    conn.close()