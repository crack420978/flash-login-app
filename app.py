from flask import Flask , render_template , request , redirect, session , url_for , flash , jsonify 
from database import store_user, verify_user , create_table , remove_user, create_table , audit_table , log_event
#from auth import register , login
from security import hash_password, is_predictable,password_vulnerability_level 
import os
app = Flask(__name__)
app.secret_key = 'your_secret_key'


create_table()
audit_table()

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
            log_event(username, "registration failed - predictable password")
            return redirect(url_for("register"))

        if vulnerable_percentage <= 25:
            # password = hash_password(password)  # Uncomment when hashing
            store_user(username, password)
            flash("Registration successful!")
            log_event(username, "registration successful")
            return redirect(url_for("login"))
        else:
            flash(f"Password vulnerability too high ({vulnerable_percentage:.2f}%). Registration blocked.")
            log_event(username, "registration failed - high vulnerability")
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

            if verify_user(username, password):
                session['user']=username
                flash(f"Login successful.")
                log_event(username , "login successful")
                return redirect(url_for("dashboard"))
                
            else:
              #  print("Invalid username or password.")
                log_event(username , "login failed")
                flash(f"Invalid username or password.")
                return redirect(url_for("login"))
            
        return render_template("login.html")
    
@app.route("/dashboard")
def dashboard():
    if "user" not in session:       # user not logged in
        return redirect(url_for("login"))
    return render_template("dashboard.html")

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
