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

@app.route("/register", methods=["GET","POST"])   
def register():
        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"]

            vul = password_vulnerability_level(password , username)
            vulnerable_percentage = vul  * 10
          #  flash(f"Password Vulnerability Level: {vulnerable_percentage}%")

            #vulnerable_percentage = password_vulnerability_level(password, username)

           # flash(f"Password Vulnerability Level: {vulnerable_percentage:.2f}%")

            if is_predictable(password , username):
                flash(f"The password is too predictable. Please choose a stronger password.")
                log_event(username , "registration failed - predictable password")
                return redirect(url_for("register"))
            
            if vulnerable_percentage <= 15:
               # password = hash_password(password) 
                store_user(username, password)
                flash(f"Registration successful!")
                log_event(username, "registration successful")
                return redirect(url_for("login"))
            else:
                flash(f"Password vulnerability too high ({vulnerable_percentage:.2f}%). Registration blocked.")
                log_event(username, "registration failed - high vulnerability")
                return redirect(url_for("register"))
        
          #  return redirect(url_for("login"))
        return render_template("register.html")

@app.route("/vulnerability_check", methods=["POST"])
def vulnerability_check():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Username and password are required."}), 400

    vul = password_vulnerability_level(password , username)
    vulnerable_percentage = round(vul  * 10,2)

    strength_percentage = round(100 - vulnerable_percentage,2)
    is_predictable_flag = is_predictable(password , username)

    return jsonify({
        "vulnerability": round(vulnerable_percentage,2),
        "strength": round(strength_percentage,2),
        "predictable": is_predictable_flag
   } ), 200


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
