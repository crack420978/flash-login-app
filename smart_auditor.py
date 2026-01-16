import re

def is_predictable(password , username):
    """
    Check if the password is predictable based on the username.
    
    Args:
    password (str): The password to check.
    username (str): The username to check against.

    Returns:
    bool: True if the password is predictable, False otherwise.
    """
    # Check if the password contains the username
    if username.lower() in password.lower():
        return True
    
    # Check for common patterns
    common_patterns = [
        r'\d{4}',  # Four consecutive digits
      #  r'[a-zA-Z]{3,}',  # Three or more letters
        r'password',  # The word 'password'
        r'1234',  # The sequence '1234'
        r'letmein',  # The phrase 'letmein'
        r'qwerty',  # The word 'qwerty'
        r'abc',  # The sequence 'abc'
        r'admin',  # The word 'admin'
       # r'user',  # The word 'user'
        r'secure',  # The word 'secure'
        r'system',  # The word 'system'
    ]
    
    for pattern in common_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return True
    
    return False


'''import hashlib
def hash_password(password):
    """
    Hash the password using SHA-256.
    
    Args:
    password (str): The password to hash.

    Returns:
    str: The hashed password in hexadecimal format.
    """
    return hashlib.sha256(password.encode()).hexdigest()'''

from argon2 import PasswordHasher
ph = PasswordHasher()
def hash_password(password):
    """
    Hash the password using Argon2.
    
    Args:
    password (str): The password to hash.

    Returns:
    str: The hashed password.
    """
    return ph.hash(password)


import sqlite3
def create_table():
    """
    Create a SQLite database table for storing usernames and hashed passwords.
    """
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
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
        return ph.verify(stored_password_hash, password)  
    return False

create_table()
print("1.Register ")
print("2.Login ")

choice = input("Enter choice: ")
if choice == '1':   
        username = input("Enter username: ")
        password = input("Enter password: ")

        if is_predictable(password, username):
            print("Password is too predictable. Please choose a stronger password.")
        else:
            store_user(username, password)
            print("User registered successfully.")
elif choice == '2':
        username = input("Enter username: ")
        password = input("Enter password: ")

        if verify_user(username, password):
            print("Login successful.")
        else:
            print("Invalid username or password.")




'''
def user_list():
    Conn = sqlite3.connect("users.db")
    cursor = Conn.cursor()
    cursor.execute("SELECT username , password_hash FROM users")
    result = cursor.fetchall()
    Conn.close()

    print("Register User List:")
    for username , password_hash in result:
        print(f"Username: {username},\nPassword Hash: {password_hash}")
        print("*=============================*")

LIST = user_list()'''


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

print("Remove a user:")
choice = input("Do you want to remove a user? (yes/no): ").strip().lower()
if choice == "yes":
    remove_user(username)
else:
    print("moving on...")   

