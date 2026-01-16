from database import store_user, verify_user , log_event
from security import is_predictable , hash_password

def register(username , password ):

    if is_predictable(password , username):
        return False , "--password is predictable--"
    success = store_user(username , password)
    if not success:
        return False , "User already exist"
    return True , "register Successful"

def login(username, password):
    stored_hash = hash_password(username)
    if not stored_hash:
        return False
    return verify_user(stored_hash, password)

def login(username, password):
    success = verify_user(username , password)
    if success:
        log_event(username , "login successful")
        return True , "login successful"
    else:
        log_event(username , "login failed")
        return False , "login failed"
    return success