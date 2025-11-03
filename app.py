from flask import Flask, render_template, flash, redirect, url_for, session
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy #pip install Flask-SQLAlchemy
from pathlib import Path
from argon2 import PasswordHasher       #pip install argon2-cffi
from flask_wtf import FlaskForm         #pip install flask-wtf
import os, string
from sqlalchemy import Text
from wtforms import StringField, SubmitField, EmailField, DateField
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

def create_admin_account():
    if(UserCredentials.query.filter_by(user_Name='admin').first() is None):
        # Admin Creds for debugging purposes.  <------------------------------------------------------------------------------------ Remove before release
        adminPass = 'admin'  # Default password
        # Hash the password (Argon2 will handle salting internally)
        adminPassHash = generateHash(adminPass)
        # Create and add the admin user
        adminUser = UserCredentials(
            user_ID=1,
            user_Name='admin',
            user_DOB = datetime(2000, 1, 1),
            user_Email='admin@email.com',
            pass_hash=adminPassHash  # Store only the hash
        )
        db.session.add(adminUser)
        db.session.commit()

# Password hash generator
def generateHash(passw):
    ph = PasswordHasher()
    return ph.hash(passw) #automatically stores the salt with the hash

# Custom WTForms validator to check password complexity 
def validatePassword(form, field):
    uppers = sum(1 for c in field.data if c.isupper()) # Count uppercase letters
    digits = sum(1 for c in field.data if c.isdigit()) # Count digits
    specials = 0
    for c in field.data:
        if ord(c) >= 32 and ord(c) <= 47: #!"#$%&'()*+,-./
            specials += 1
        elif ord(c) >= 58 and ord(c) <= 64: #:;<=>?@
            specials += 1
        elif ord(c) >= 91 and ord(c) <= 96: #[\]^_`
            specials += 1
        elif ord(c) >= 123 and ord(c) <= 126: #{|}~
            specials += 1
# "raise ValidationError" is not working properly, so using flash messages for now
    if len(field.data) < passLen: # Check length
        print('len error')
        flash('Password must contian at least ' + str(passLen) + ' characters')
        raise ValidationError('Password must contian at least ' + str(passLen) + ' characters')
    elif uppers < passCase: # Check uppercase letters
        print('case error')
        flash('Password must contain at least ' + str(passCase) + ' upper-case character')
        raise ValidationError('Password must contain at least ' + str(passCase) + ' upper-case character')
    elif digits < passNum: # Check digits
        print('num error')
        flash('Password must contain at least ' + str(passNum) + ' number')
        raise ValidationError('Password must contain at least ' + str(passNum) + ' number')
    elif specials < passSpec: # Check special characters
        print('spec error')
        flash('Password must contain at least ' + str(passSpec) + ' special character')
        raise ValidationError('Password must contain at least ' + str(passSpec) + ' special character')

# Creating a model for user credentials
class  UserCredentials(db.Model):
    user_ID = db.Column(db.Integer, primary_key=True)
    user_Name = db.Column(db.String(50),nullable=False, unique=True)
    user_DOB = db.Column(db.DateTime, nullable=True)
    user_Email = db.Column(db.String(60), nullable=False, unique=True)
    pass_hash = db.Column(db.String, nullable=False) #should be salted already
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    network_data = db.relationship('network_Data', backref='userCred', lazy=True)

# Create a registration form class
class RegisterForm (FlaskForm):
    username = StringField("Username: ", validators=[data_required()])
    email = EmailField("Email: ", validators=[data_required()])
    dob = DateField("Date of Birth: ", format='%Y-%m-%d', validators=[data_required()])
    password = StringField("Password: ", validators=[data_required(), validatePassword])
    submit = SubmitField("Create Account")
    
# Create a login form class
class LoginForm (FlaskForm):
    username = StringField("Username or Email: ", validators=[data_required()])
    password = StringField("Password: ", validators=[data_required()])
    submit = SubmitField("Sign in")

# Create a forgotpw form class
class ForgotpwForm (FlaskForm):
    username = StringField("Username or Email: ", validators=[data_required()])
    newpassword = StringField("New Password: ", validators=[data_required(), validatePassword])  # ADD validatePassword
    submit = SubmitField("Reset Password")  # Change button text

#Creates a context to manage the database
with app.app_context():
    #Drops all tables from the database
    db.drop_all()

    #Adds tables out of all the modles in the database, unless they already exist
    db.create_all()

    # Create default admin account
    create_admin_account()

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
        flash("You are already logged in.")
        return redirect(url_for('homepage'))
    else:
        # Initializes values to None 
        username = None
        password = None
        passHash = None
        # Specifies the form class to use
        form = LoginForm()

        # Checks if the submit button has been pressed
        if form.validate_on_submit():
            # Try to find user by username OR email
            user = UserCredentials.query.filter((UserCredentials.user_Name == form.username.data) | (UserCredentials.user_Email == form.username.data)).first()
            # if user exists
            if user:
                # A new hash is generated with the password entered into the login form, using the same salt that is within the database
                try: 
                    if form.password.data.lower() == "'or 1 = 1":
                        flash("Nice Try.")
                        return render_template('log_in.html', form=form, username = username, passHash = passHash)
                    ph = PasswordHasher()
                    if ph.verify(user.pass_hash, form.password.data):
                        session['username'] = user.user_Name
                        session['user_id'] = user.user_ID
                        flash("Welcome, " + session.get('username') + "!")
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
        # Re-rendering the login page after a failed login attempt
        return render_template('log_in.html', form=form, username = username, passHash = passHash)

#======================= Create_Account =======================#
@app.route('/Create_Account',  methods=['POST', 'GET'])
def create_account():
    if session.get('username'):
        flash("You are already logged in.")
        return redirect(url_for('homepage'))
    else: 
        username = None
        dob = None
        email = None
        password = None
        passHash = None
        form = RegisterForm()
        # Checks if the submit button has been pressed
        # Add this debug print to see what's in the form data
        if form.is_submitted():
            print('Form submitted')
            print(f'Form errors: {form.errors}')
            print(f'Username data: {form.username.data}')
            print(f'Email data: {form.email.data}')
            print(f'DOB data: {form.dob.data}')
            print(f'Password data: {form.password.data}')

        if form.validate_on_submit():
            print('form validated')
            # Check if username already exists
            existing_username = UserCredentials.query.filter_by(user_Name=form.username.data).first()
            # Queries the database to see if the email already exists in the database
            existing_email = UserCredentials.query.filter_by(user_Email=form.email.data).first()
            if existing_username is None:
                print('username is available')
                if existing_email is None:
                    print('email is available as well')
                    passHash = generateHash(form.password.data)
                    # A database object is created with the user's information
                    user = UserCredentials(user_Name = form.username.data, user_DOB = form.dob.data, user_Email = form.email.data, pass_hash = passHash)
                    session['username'] = user.user_Name   
                    # The newly created user object is added to a database session, and committed as an entry to the user_credentials table
                    db.session.add(user)
                    db.session.commit()
                    session['user_id'] = (UserCredentials.query.filter_by(user_Name = form.username.data).first()).user_ID

                    # The user is logged in and redirected to the homepage
                    flash("Account created successfully! Welcome, " + session.get('username') + "!")
                    return redirect(url_for('homepage'))
                
                # If the email that was entered is associated with an existing user account, the user is instead brought back to the registration page
                else:
                    flash("Error: Email already in use.")
            else:
                flash("Error: Username already in use.")

            #Clearing the form data after it has been submitted
            username = form.username.data
            form.username.data = ''
            dob = form.dob.data
            form.dob.data = ''
            email = form.email.data
            form.email.data = ''
            password = form.password.data
            form.password.data = ''

        # Re-rendering the account creation page after an unsuccessful submission
        return render_template('create_acct.html', form=form, username = username, dob = dob, email = email, passHash = passHash)

#======================= Forgot_Password =======================#
@app.route('/Forgot_Password', methods=['POST', 'GET'])  # ADD methods parameter
def forgotpw():
    if session.get('username'):
        flash("You are already logged in.")
        return redirect(url_for('homepage'))
    else:
        # Initializes values to None 
        username = None
        newpassword = None
        passHash = None
        form = ForgotpwForm()

        #Checks if the submit button has been pressed
        if form.validate_on_submit():
            # Try to find user by username OR email
            user = UserCredentials.query.filter((UserCredentials.user_Name == form.username.data) | (UserCredentials.user_Email == form.username.data)).first()
            if user:
                try: 
                    # SQL injection easter egg check
                    if form.newpassword.data.lower() == "'or 1 = 1":
                        flash("Nice Try.")
                        return render_template('forgotpw.html', form=form, username=username, passHash=passHash)

                    # Generate new password hash
                    passHash = generateHash(form.newpassword.data)
                    
                    # UPDATE the existing user's password instead of creating a new user
                    user.pass_hash = passHash
                    db.session.commit()
                    
                    flash("Password reset successfully! Please log in with your new password.")
                    return redirect(url_for('log_in'))

                except Exception as e:
                    print(f"Error during password reset: {e}")
                    flash("Error: Could not reset password. Please try again.")

            else:
                if form.newpassword.data.lower() == "'or 1 = 1":
                    flash("Nice try.")
                else:
                    flash("Error: User does not exist. Please check your username or email.")

            #Clearing the form data after it has been submitted
            username = form.username.data
            form.username.data = ''
            newpassword = form.newpassword.data
            form.newpassword.data = ''

        return render_template('forgotpw.html', form=form, username=username, passHash=passHash)


#======================= Homepage =======================#
@app.route('/Homepage')
def homepage():
    if session.get('username'):
        return render_template('homepage.html')
    else:
        flash("Please log in to access the homepage.")
        return redirect(url_for('log_in'))
    
#======================= Parts =======================#
@app.route('/Homepage/Parts')
def parts():
    if session.get('username'):
        flash("Welcome, " + session.get('username') + "! This page is currently under development!")
        return render_template('parts.html')
    else:
        flash("Please log in to access our parts.")
        return redirect(url_for('log_in'))
    
#======================= Cart =======================#
@app.route('/Homepage/Cart')
def cart():
    if session.get('username'):
        flash("Welcome, " + session.get('username') + "! This page is currently under development!")
        return render_template('cart.html')
    else:
        flash("Please log in to access your cart.")
        return redirect(url_for('log_in'))
    
#======================= Orders =======================#
@app.route('/Homepage/Orders')
def orders():
    if session.get('username'):
        flash("Welcome, " + session.get('username') + "! This page is currently under development!")
        return render_template('orders.html')
    else:
        flash("Please log in to access your orders.")
        return redirect(url_for('log_in'))
    
#======================= Account =======================#
@app.route('/Homepage/Account')
def account():
    if session.get('username'):
        flash("Welcome, " + session.get('username') + "! This page is currently under development!")
        return render_template('account.html')
    else:
        flash("Please log in to access your account.")
        return redirect(url_for('log_in'))

#======================= Logout =======================#
@app.route('/logout')
def log_out():
    if session.get('username'):
        session.pop('username')
        flash("You have been logged out.")
    return redirect(url_for('log_in'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8000)