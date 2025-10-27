from flask import Flask, render_template, flash, redirect, url_for, session
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy #pip install Flask-SQLAlchemy
from pathlib import Path
from argon2 import PasswordHasher       #pip install argon2-cffi
from flask_wtf import FlaskForm         #pip install flask-wtf
import os, string
from sqlalchemy import Text
from wtforms import StringField, SubmitField, EmailField
from wtforms.validators import data_required, ValidationError
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'insecurePassword'

#Configuring the Database location
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{Path(__file__).parent / './Databases/userAccounts.db'}"

#Initialize the database
db = SQLAlchemy(app)

# Setting default password policy
passLen = 9
passCase = 1
passNum = 1
passSpec = 1

# Password hash generator
# Function to hash a password
def generateHash(passw):
    ph = PasswordHasher()
    return ph.hash(passw) #automatically stores the salt with the hash

def requires_confirmation(route):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if route == 'delete_account_confirm':
                if not session.get('delete_account_confirmed'):
                    flash("Please confirm information to delete your account.")
                    return redirect(url_for('settings_delete_confirm'))
            else: 
                if not session.get('user_authenticated'):
                    flash("Please confirm information in order to access this page.")
                    return redirect(url_for('settings_confirm'))  # Change 'login' to your login route
                # Check if the route is the delete account confirmation
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Function to strip multiple characters from a string
def stripChars(input: string, strip: string):
    begStr = str(input)
    chars = str(strip)

    for ch in chars:
        if ch in begStr:
            begStr = begStr.replace(ch, '')
            
    return begStr

# Custom WTForms validator to check password complexity 
def validatePassword(form, field):
    uppers = sum(1 for c in field.data if c.isupper())
    digits = sum(1 for c in field.data if c.isdigit())
    specials = 0
    for c in field.data:
        if ord(c) >= 32 and ord(c) <= 47:
            specials += 1
        elif ord(c) >= 58 and ord(c) <= 64:
            specials += 1
        elif ord(c) >= 91 and ord(c) <= 96:
            specials += 1
        elif ord(c) >= 123 and ord(c) <= 126:
            specials += 1
    if len(field.data) < passLen:
        print('len error')
        flash('Password must contian at least ' + str(passLen) + ' characters')
        raise ValidationError('Password must contian at least ' + str(passLen) + ' characters')
    elif uppers < passCase:
        print('case error')
        flash('Password must contain at least ' + str(passCase) + ' upper-case character')
        raise ValidationError('Password must contain at least ' + str(passCase) + ' upper-case character')
    elif digits < passNum:
        print('num error')
        flash('Password must contain at least ' + str(passNum) + ' number')
        raise ValidationError('Password must contain at least ' + str(passNum) + ' number')
    elif specials < passSpec:
        print('spec error')
        flash('Password must contain at least ' + str(passSpec) + ' special character')
        raise ValidationError('Password must contain at least ' + str(passSpec) + ' special character')
    
def split_integer_at_rightmost_digit(input_integer):
    # Convert the integer to a string
    input_str = str(input_integer)

    # Extract the rightmost digit
    rightmost_digit = int(input_str[-1])

    # Extract everything to the left of the rightmost digit
    left_of_rightmost_digit_str = input_str[:-1]

    # Check if the string is not empty before converting to int
    if left_of_rightmost_digit_str:
        left_of_rightmost_digit = int(left_of_rightmost_digit_str)
    else:
        # Handle the case when the string is empty
        left_of_rightmost_digit = 0  # or any default value you prefer

    return left_of_rightmost_digit, rightmost_digit

# Configure upload folders
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'Databases')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the Data model includes PCAP-specific fields (replace existing)
class network_Data(db.Model):
    ID = db.Column(db.Integer, primary_key=True)
    user_ID = db.Column(db.Integer, db.ForeignKey('user_credentials.user_ID'))
    pcap_filename = db.Column(db.String(100), nullable=False)   # e.g., "1.pcap"
    #pcap_path = db.Column(db.String(200), nullable=False)   # e.g., ".../Databases/1/1/1.pcap"
    #final_path = db.Column(db.String(200))    # For extracted features e.g., ".../Databases/1/1/1_final.csv"
    results_path = db.Column(db.String(200)) #e.g, ".../Databases/1/1/1_results.csv"
    visualization = db.Column(db.Text) #e.g, ".../Databases/1/1/XGB_feat_importance.png"
    threat_type = db.Column(db.String(50)) # e.g., "BENIGN", "MALWARE", "DOS", etc.
    accuracy = db.Column(db.Float)
    malicious_records = db.Column(db.Integer) # Count of malicious flows
    total_flows = db.Column(db.Integer)     # Total flows analyzed
    analysis_results = db.Column(db.Text)  # Stores JSON-serialized DataFrame
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)

#Creating a model for user credentials
class  UserCredentials(db.Model):
    user_ID = db.Column(db.Integer, primary_key=True)
    user_Name = db.Column(db.String(50),nullable=False)
    user_Email = db.Column(db.String(60), nullable=False, unique=True)
    #user_Phone = db.Column(db.Integer, unique=True)
    #pass_salt = db.Column(db.Integer, nullable=False, unique=True)
    pass_hash = db.Column(db.String, nullable=False) #should be salted already
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    network_data = db.relationship('network_Data', backref='userCred', lazy=True)

#Create a registration form class
class RegisterForm (FlaskForm):
    username = StringField("Username: ", validators=[data_required()])
    email = EmailField("Email: ", validators=[data_required()])
    #phone = TelField("Phone: ")
    password = StringField("Password: ", validators=[data_required(), validatePassword])
    submit = SubmitField("Create Account")
    
#Create a login form class
class LoginForm (FlaskForm):
    username = StringField("Username: ", validators=[data_required()])
    password = StringField("Password: ", validators=[data_required()])
    submit = SubmitField("Sign in")

#Creates a context to manage the database
with app.app_context():
    #Drops all tables from the database
    db.drop_all()

    #Adds tables out of all the modles in the database, unless they already exist
    db.create_all()

    #LoginCredentials.__table__.create(db.engine)

    #Drops one specific table
    #LoginCredentials.__table__.drop(db.engine)
    pass

#============================================== App routes
#============================================================================================================== Default/Login
#Handles the backend of the login page
#======================= Login =======================#
@app.route('/', methods=['POST', 'GET'])
def log_in():
    if session.get('username'):
        return redirect(url_for('homepage'))
    else:
        if(UserCredentials.query.filter_by(user_Name='admin').first() is None):
            # Admin Creds for debugging purposes.  <------------------------------------------------------------------------------------ Remove before release
            #adminSalt = generateSalt()
            adminPass = 'admin'  # Default password (change this before release)
            # Hash the password (Argon2 will handle salting internally)
            adminPassHash = generateHash(adminPass)
            # Create and add the admin user
            adminUser = UserCredentials(
                user_ID=1,
                user_Name='admin',
                user_Email='admin@email.com',
                pass_hash=adminPassHash  # Store only the hash
            )
            db.session.add(adminUser)
            db.session.commit()


            #db.session.add(Preferences(user_ID= UserCredentials.query.filter_by(user_Name='admin').first().user_ID, notifications= 0, study_time= 3600, break_time= 600))
            #db.session.commit()
        # Initializes values to None 
        username = None
        password = None
        passHash = None
        #salt = None
        # Specifies the form class to use
        form = LoginForm()

        #Checks if the submit button has been pressed
        if form.validate_on_submit():
            # Queries the database to see if the username exists
            user = UserCredentials.query.filter_by(user_Name=form.username.data).first()
            # if user exists
            if user:
                # The salt and hash associated with the user's profile are taken from the database
                #salt = user.pass_salt
                #userHash = user.pass_hash
                # A new hash is generated with the password entered into the login form, using the same salt that is within the database
                try: 
                    if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice Try.")
                        return render_template('log_in.html', form=form, username = username, passHash = passHash) #salt = salt
                    ph = PasswordHasher()
                    if ph.verify(user.pass_hash, form.password.data):
                        session['username'] = user.user_Name
                        session['user_id'] = user.user_ID
                        session['user_authenticated'] = None
                        #session['delete_account_confirmed'] = None
                        return redirect(url_for('homepage'))
                except:
                    flash("Error: the information you entered does not match our records")

            else:
                if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice try.")
                else:
                    flash("Error: User does not exist the information you entered does not match our records.")

            #Clearing the form data after it has been submitted
            username = form.username.data
            form.username.data = ''
            password = form.password.data
            form.password.data = ''
            session['user_authenticated'] = None
            #session['delete_account_confirmed'] = None
        # Re-rendering the login page after a failed login attempt
        return render_template('log_in2.html', form=form, username = username, passHash = passHash) #salt = salt

#======================= Create_Account =======================#
@app.route('/create_account',  methods=['POST', 'GET'])
def Register():
    username = None
    email = None
    #phone = None
    password = None
    passHash = None
    #salt = generateSalt()
    form = RegisterForm()

    # Checks if the submit button has been pressed
    if form.validate_on_submit():
        # Queries the database to see if the email already exists in the database
        user = UserCredentials.query.filter_by(user_Email=form.email.data).first()
        if user is None:
            # If no user exists with the email entered, checks to see if the phone number exists in the database
            #user = UserCredentials.query.filter_by(user_Phone=form.phone.data).first()
            #if user is None:
            # If no user exists with the phone nunmber entered, A hash is generated from the user's password with a random salt
            passHash = generateHash(form.password.data) #, salt
            # A database object is created with the user's information
            user = UserCredentials(user_Name = form.username.data, user_Email = form.email.data, pass_hash = passHash) #pass_salt = salt
            session['username'] = user.user_Name                
            
            # The newly created user object is added to a database session, and committed as an entry to the user_credentials table
            db.session.add(user)
            db.session.commit()
            session['user_id'] = (UserCredentials.query.filter_by(user_Name = form.username.data).first()).user_ID

            # A database object is created alongside the user's account to store their preferences (initialized with default values).
            #prefs = Preferences(user_ID= session.get('user_id'), notifications= 0, study_time= 3600, break_time= 600)
            #db.session.add(prefs)
            #db.session.commit()
            # The user is logged in and redirected to the homepage
            session['user_authenticated'] = None
            #session['delete_account_confirmed'] = None
            return redirect(url_for('homepage'))
            
            # If the phone number that was entered is associated with an existing user account, the user is instead brought back to the registration page
            #else:
                #flash("Error: Phone number already in use.")
        # If the email that was entered is associated with an existing user account, the user is instead brought back to the registration page
        else:
            flash("Error: Email already in use.")

        #Clearing the form data after it has been submitted
        username = form.username.data
        form.username.data = ''
        email = form.email.data
        form.email.data = ''
        #phone = form.phone.data
        #form.phone.data = ''
        password = form.password.data
        form.password.data = ''

     # Re-rendering the account creation page after an unsuccessful submission
    session['user_authenticated'] = None
    #session['delete_account_confirmed'] = None
    return render_template('create_acct2.html', form=form, username = username, email = email, passHash = passHash) #, salt = salt

#======================= (NOT IMPLEMENTED) Forgot_Password =======================#
@app.route('/Forgot_Password')
def forgotpw():
    if session.get('username'):
        return redirect(url_for('homepage'))
    else:
        # Initializes values to None 
        username = None
        password = None
        passHash = None
        #salt = None
        # Specifies the form class to use
        form = LoginForm()

        #Checks if the submit button has been pressed
        if form.validate_on_submit():
            # Queries the database to see if the username exists
            user = UserCredentials.query.filter_by(user_Name=form.username.data).first()
            # if user exists
            if user is not None:
                # The salt and hash associated with the user's profile are taken from the database
                #salt = user.pass_salt
                userHash = user.pass_hash
                # A new hash is generated with the password entered into the login form, using the same salt that is within the database
                passHash = generateHash(form.password.data) #, salt
                # The newly generated hash is compared to the hash within the database
                if passHash == userHash:
                    session['username'] = user.user_Name
                    session['user_id'] = user.user_ID
                    session['user_authenticated'] = None
                    session['delete_account_confirmed'] = None
                    # If the hashes matched, the user is logged in and redirected to the home page
                    return redirect(url_for('homepage'))
                #Otherwise, the user is not redirected and the form is cleared
                else:
                    #SQL injection easter egg
                    if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice try.")
                    else:
                        flash("Error: the information you entered does not match our records.")
            else:
                if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice try.")
                else:
                    flash("Error: the information you entered does not match our records.")

            #Clearing the form data after it has been submitted
            username = form.username.data
            form.username.data = ''
            password = form.password.data
            form.password.data = ''
        # Re-rendering the login page after a failed login attempt
        session['user_authenticated'] = None
        session['delete_account_confirmed'] = None
        return render_template('forgotpw.html', form=form, username = username, passHash = passHash) #, salt = salt

#======================= Homepage =======================#
@app.route('/Homepage')
def homepage():
    if session.get('username'):
        session['user_authenticated'] = None
        #session['delete_account_confirmed'] = None
        return render_template('homepage2.html')
    else:
        flash("Please log in to access the homepage.")
        return redirect(url_for('log_in'))
    
""" #======================= Test =======================#
@app.route('/test')
def test():
    return render_template('index2.html')

#======================= Test =======================#
@app.route('/test2')
def log_in2():
    return render_template('log_in2.html')

#======================= Test =======================#
@app.route('/test3')
def test3():
    return render_template('create_acct2.html') """

#======================= Logout =======================#
@app.route('/logout')
def log_out():
    if session.get('username'):
        session.pop('username')
    return redirect(url_for('log_in'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8000)