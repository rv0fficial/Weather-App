from flask import Flask, render_template, request, url_for, redirect, session
from pymongo import MongoClient
import bcrypt
import re #gpt

#For Jinja2
import os 
from jinja2 import FileSystemLoader, Environment

from html import escape  # Import escape for HTML input sanitization

#set app as a Flask instance 
app = Flask(__name__)
#encryption relies on secret keys so they could be run
app.secret_key = "testing"

# Set the template directory explicitly (Jinja2)
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = Environment(loader=FileSystemLoader(template_dir))

# #connect to your Mongo DB database
def MongoDB():
    client = MongoClient("mongodb+srv://admin:<password>@cluster0.cislfvh.mongodb.net/?retryWrites=true&w=majority")
    db = client.get_database('total_records')
    records = db.register
    return records
# records = MongoDB()


##Connect with Docker Image###
def dockerMongoDB():
    client = MongoClient(host='test_mongodb',
                            port=27017, 
                            username='root', 
                            password='pass',
                            authSource="admin")
    db = client.users
    pw = "test123"
    hashed = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt())
    records = db.register
    records.insert_one({
        "name": "Test Test",
        "email": "test@yahoo.com",
        "password": hashed
    })
    return records

records = dockerMongoDB()

# gpt Email Specific Format Checks
def checkEmail(email):
    emailPattern = r"^[^ ]+@[^ ]+\.[a-z]{2,3}$"

    if not re.match(emailPattern, email):
        return False
    return True

# gpt Password Specific Format Checks
def createPass(password):
    passPattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"

    if not re.match(passPattern, password):
        return False
    return True

# Sanitize user inputs
def sanitize_input(input_string):
    return escape(input_string)

# Input Validation Function
def is_valid_input(input_string):
    # Check for disallowed characters in the input string
    disallowed_chars = ['$', ':', '<', '>', '(', ')', '[', ']', '{', '}', ';', '=', '&', '|', '!', '`', '"', "'", '\\', '/', '#', '%', '?', ',']
    return all(char not in input_string for char in disallowed_chars)

#assign URLs to have a particular route 
@app.route("/", methods=['post', 'get'])
def index():
    message = ''
    #if method post in index
    if "email" in session:
        return redirect(url_for("logged_in"))
    
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        # Additional validation for user input
        invalid_fields = []

        if not is_valid_input(user):
            invalid_fields.append('User')
        if not is_valid_input(email):
            invalid_fields.append('Email')
        if not is_valid_input(password1):
            invalid_fields.append('Password 1')
        if not is_valid_input(password2):
            invalid_fields.append('Password 2')

        if invalid_fields:
            invalid_input_message = 'Invalid characters in the following fields: ' + ', '.join(invalid_fields)
            return jinja_env.get_template('index.html').render(message=invalid_input_message)

        # After validation, sanitize the input for security
        user = sanitize_input(user)
        email = sanitize_input(email)

        # The input is now considered safe for further processing

        # gpt Email Specific Format Checks
        if not checkEmail(email): 
            message = 'Invalid email format. Please provide a valid email address.'
            print("Email validation failed:", message)  # Add this line for debugging
            #Modify this line to use Jinja2 for rendering the index template
            return jinja_env.get_template('index.html').render(message=message)
        
        # gpt Password Specific Format Checks
        if not createPass(password1):
            message = 'Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one digit, and one special character.'
            print("Password validation failed:", message)  # Add this line for debugging
            #Modify this line to use Jinja2 for rendering the index template
            return jinja_env.get_template('index.html').render(message=message)

        #if found in database showcase that it's found 
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            #Modify this line to use Jinja2 for rendering the index template
            return jinja_env.get_template('index.html').render(message=message)
        if email_found:
            message = 'This email already exists in database'
            #Modify this line to use Jinja2 for rendering the index template
            return jinja_env.get_template('index.html').render(message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            #Modify this line to use Jinja2 for rendering the index template
            return jinja_env.get_template('index.html').render(message=message)
        else:
            #hash the password and encode it
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            #assing them in a dictionary in key value pairs
            user_input = {'name': user, 'email': email, 'password': hashed}
            #insert it in the record collection
            records.insert_one(user_input)
            
            #find the new created account and its email
            user_data = records.find_one({"email": email})
            new_email = user_data['email']
            #if registered redirect to logged in as the registered user
            #Modify this line to use Jinja2 for rendering the logged_in template
            return jinja_env.get_template('logged_in.html').render(email=new_email)
    #Modify this line to use Jinja2 for rendering the index template
    return jinja_env.get_template('index.html').render()

@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return redirect(url_for("logged_in"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Additional validation for user input
        invalid_fields = []

        if not is_valid_input(email):
            invalid_fields.append('Email')
        if not is_valid_input(password):
            invalid_fields.append('Password')

        if invalid_fields:
            invalid_input_message = f'Invalid characters in the following fields: {", ".join(invalid_fields)}'
            return jinja_env.get_template('login.html').render(message=invalid_input_message)

        # After validation, sanitize the input for security
        email = sanitize_input(email)

        # The input is now considered safe for further processing

        # gpt Email Specific Format Checks (When the above sanitization & validation parts were implemented,this was also added)
        if not checkEmail(email):
            message = 'Invalid email format. Please provide a valid email address.'
            return jinja_env.get_template('login.html').render(message=message)

        #check if email exists in database
        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password']
            #encode the password and check if it matches
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                return redirect(url_for('logged_in'))
            else:
                if "email" in session:
                    return redirect(url_for("logged_in"))
                message = 'Wrong password'
                #Modify this line to use Jinja2 for rendering the login template
                return jinja_env.get_template('login.html').render(message=message)
        else:
            message = 'Email not found'
            # Modify this line to use Jinja2 for rendering the login template
            return jinja_env.get_template('login.html').render(message=message)
    # Modify this line to use Jinja2 for rendering the login template
    return jinja_env.get_template('login.html').render(message=message)

@app.route('/logged_in')
def logged_in():
    if "email" in session:
        email = session["email"]
        # Modify this line to use Jinja2 for rendering the logged_in template
        return jinja_env.get_template('logged_in.html').render(email=email)
    else:
        return redirect(url_for("login"))

@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        return render_template("signout.html")
    else:
        return render_template('index.html')




if __name__ == "__main__":
  app.run(debug=True, host='0.0.0.0', port=5000)
