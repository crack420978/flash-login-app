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
       r'[a-zA-Z]{2,}',  # Three or more letters
        r'password',  # The word 'password'
        r'1234',  # The sequence '1234'
        r'letmein',  # The phrase 'letmein'
        r'qwerty',  # The word 'qwerty'
        r'abc',  # The sequence 'abc'
        r'admin',  # The word 'admin'
        r'user',  # The word 'user'
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

def password_vulnerability_level(password ,username):
    score =0

    #length
    if len(password) >= 12:
        score += 25
    elif len(password) >=8:
        score+=10
    if re.search(r'[A-Z]',password):
        score += 15
    if re.search(r'[a-z]',password):
        score += 15
    if re.search(r'[!@#$%^&*-=+/]',password):
        score += 15
    if re.search(r'\d',password):
        score += 15
    
    if username.lower() not in password:
        score += 10
    
    common_password = [
        r'password' , r'qwert' , r'1234567890' , r'admin' , r'abc' 
    ]

    for pattern in common_password:
        if re.search(pattern , password , re.IGNORECASE):
            score -= 30
    


    # score
    score = max(0, min(score, 100))

    return score // 10