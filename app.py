from flask import Flask , render_template , request , redirect, session , url_for , flash , jsonify 
#from database import store_user, verify_user , create_table , remove_user, create_table , audit_table , log_event
from datetime import datetime
from pymongo import MongoClient
from security import hash_password, is_predictable,password_vulnerability_level 
import os
from argon2 import PasswordHasher
ph = PasswordHasher()
from argon2.exceptions import VerifyMismatchError
app = Flask(__name__)
app.secret_key = 'your_secret_key'

client=MongoClient("mongodb://localhost:27017/")
db=client["smart_auditor"]
#client = client["user_db"]

users_collection = db["users"]
logs_collection = db["audit_logs"]

print("mongo DB connected successfully")



@app.route("/")
def home():
    return render_template("index.html")

#print("1.Register ")
#print("2.Login ")

#choice = input("Enter choice: ")
#if choice == '1':
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        vul = password_vulnerability_level(password, username)
        strength_percentage = round(vul * 10, 2)  # Scale to 0-100
        vulnerable_percentage = round(100 - strength_percentage, 2) # Scale to 0-100

        if is_predictable(password, username):
            flash("The password is too predictable. Please choose a stronger password.")
        #    log_event(username, "registration failed - predictable password")
            return redirect(url_for("register"))

        if vulnerable_percentage <= 25:
            # password = hash_password(password)  # Uncomment when hashing
            user = {
                "username": username,
                "password": ph.hash(password),
                "created_at": datetime.now()
            }
            users_collection.insert_one(user)
            flash("Registration successful!")
          #  log_event(username, "registration successful")
            return redirect(url_for("login"))
        else:
            flash(f"Password vulnerability too high ({vulnerable_percentage:.2f}%). Registration blocked.")
         #   log_event(username, "registration failed - high vulnerability")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/check_password", methods=["POST"])
def check_password():
    """
    Real-time password vulnerability check for JS fetch
    """
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    score = 100
        # Calculate vulnerability and strength using the same logic as registration
    vul = password_vulnerability_level(password, username)

    strength_percentage = round(vul * 10, 2)  # Strength percentage
    vulnerable_percentage = round(100 - strength_percentage, 2) # Inverse for vulnerability

    return jsonify({
        "vulnerability": vulnerable_percentage,
        "strength": strength_percentage
    })

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        users = users_collection.find_one({"username": username})
        
        if users:
            try:
                # Verify password using Argon2
                ph.verify(users["password"], password)

                session["user"] = username
                flash("Login successful!")

                # Log event
                logs_collection.insert_one({
                    "username": username,
                    "action": "user login",
                    "timestamp": datetime.now()
                })

                return redirect(url_for("dashboard"))

            except VerifyMismatchError:
                # Password did not match
                flash("Invalid username or password")
                logs_collection.insert_one({
                    "username": username,
                    "action": "failed login attempt",
                    "timestamp": datetime.now()
                })
                return redirect(url_for("login"))

        else:
            flash("Invalid username or password")
            return redirect(url_for("login"))

    return render_template("login.html")
    
@app.route("/dashboard")
def dashboard():
    if "user" not in session:       # user not logged in
        return redirect(url_for("login"))
    return render_template("dashboard.html")


@app.route("/admin/logs")
def view_logs():
    if "user" not in session:
        return redirect(url_for("login"))
    
    # For simplicity, we assume any logged-in user can view logs. In production, check for admin role.
    logs = list(logs_collection.find().sort("timestamp", -1))  # Get logs sorted by timestamp
    return render_template("logs.html", logs=logs)

@app.route("/logout")
def logout():
    session.pop("user", None)   # remove user from session
    flash("You have been logged out")
    return redirect(url_for("login"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)



'''
print("Remove a user:")
choice = input("Do you want to remove a user? (yes/no): ").strip().lower()
if choice == "yes":
    remove_user()
else:
    print("moving on...")   
    '''
