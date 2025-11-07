from flask import Flask, render_template, flash, redirect, url_for, session, jsonify, request
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy #pip install Flask-SQLAlchemy
from pathlib import Path
from argon2 import PasswordHasher       #pip install argon2-cffi
from flask_wtf import FlaskForm         #pip install flask-wtf
import os, string
from sqlalchemy import Text
from wtforms import StringField, SubmitField, EmailField, DateField, IntegerField, FloatField, TextAreaField, SelectField
from wtforms.validators import data_required, ValidationError, Optional
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'insecurePassword'

#Configuring the Database location
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{Path(__file__).parent / './Databases/userAccounts.db'}"
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

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
            user_Role='root_admin',
            user_Name='admin',
            user_DOB = datetime(2000, 1, 1),
            user_Address='123 Admin St',
            user_City='Admin City',
            user_State='Admin State',
            user_Zip='12345',
            user_Email='admin@email.com',
            pass_hash=adminPassHash  # Store only the hash
        )
        db.session.add(adminUser)
        db.session.commit()

# Confirm admin role
def logged_in_required():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('username'):
                flash("You must be logged in to access that page.")
                return redirect(url_for('log_in'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Confirm admin role
def admin_required():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('username'):
                flash("You must be logged in to access that page.")
                return redirect(url_for('log_in'))
            user = UserCredentials.query.filter((UserCredentials.user_Name == session.get('username'))).first()
            if user and user.user_Role != 'root_admin':
                flash("You must be an admin to acccess that page.")
                return redirect(url_for('homepage'))
            flash("Welcome to the Admin page,  " + session.get('username') + "!")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Password hash generator
def generateHash(passw):
    ph = PasswordHasher()
    return ph.hash(passw) # automatically stores the salt with the hash

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
    user_Role = db.Column(db.String(20), nullable=False, default='standard_user')
    user_Name = db.Column(db.String(50),nullable=False, unique=True)
    user_DOB = db.Column(db.DateTime, nullable=True)
    user_Address = db.Column(db.String(100), nullable=True)
    user_City = db.Column(db.String(50), nullable=True)
    user_State = db.Column(db.String(50), nullable=True)
    user_Zip = db.Column(db.String(10), nullable=True)
    user_Email = db.Column(db.String(60), nullable=False, unique=True)
    pass_hash = db.Column(db.String, nullable=False) # should be salted already
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

# Creating a model for products
class Products(db.Model):
    product_ID = db.Column(db.Integer, primary_key=True)
    product_Name = db.Column(db.String(100), nullable=False)
    product_Brand = db.Column(db.String(100), nullable=True)
    product_Type = db.Column(db.String(50), nullable=False)
    product_Description = db.Column(db.Text, nullable=True)
    product_Stock = db.Column(db.Integer, nullable=False)
    product_Price = db.Column(db.Float, nullable=False)
    product_Image = db.Column(db.Text, nullable=True) # Path to Image
    product_Added = db.Column(db.DateTime, default=datetime.utcnow)

# Create a registration form class
class RegisterForm (FlaskForm):
    username = StringField("Username: ", validators=[data_required()])
    email = EmailField("Email: ", validators=[data_required()])
    dob = DateField("Date of Birth: ", format='%Y-%m-%d', validators=[data_required()])
    address = StringField("Address: ", validators=[data_required()])
    city = StringField("City: ", validators=[data_required()])
    state = StringField("State: ", validators=[data_required()])
    zip = StringField("Zip Code: ", validators=[data_required()])
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

class AccountForm (FlaskForm):
    new_username = StringField("New Username:", validators=[data_required()])
    new_email = EmailField("New Email: ", validators=[data_required()])
    new_address = StringField("New Address: ", validators=[data_required()])
    new_city = StringField("New City: ", validators=[data_required()])
    new_state = StringField("New State: ", validators=[data_required()])
    new_zip = StringField("New Zip Code: ", validators=[data_required()])
    new_password = StringField("New Password: ")
    submit = SubmitField("Apply")

class AccountFormConfirm (FlaskForm):
    username = StringField("Confirm Username: ", validators=[data_required()])
    password = StringField("Confirm Password: ", validators=[data_required()])
    submit = SubmitField("Confirm")

class AdminUserForm (FlaskForm):
    user_id = StringField("User ID: ", validators=[data_required()])
    new_role = SelectField("New Role: ", choices=[
        ('standard_user', 'Standard User'),
        ('root_admin', 'Root Admin')
    ], validators=[data_required()])
    submit = SubmitField("Apply Changes")

class AdminProductForm (FlaskForm):
    product_id = IntegerField("Product ID", validators=[Optional()])  # For editing existing products
    product_name = StringField("Product Name", validators=[data_required()])
    product_brand = StringField("Product Brand", validators=[data_required()])
    product_type = SelectField("Product Type", choices=[
        ('CPU', 'CPU'),
        ('GPU', 'GPU'),
        ('RAM', 'RAM'),
        ('Motherboard', 'Motherboard'),
        ('Storage', 'Storage'),
        ('PSU', 'Power Supply'),
        ('Case', 'Case'),
        ('Cooling', 'Cooling'),
        ('Other', 'Other')
    ], validators=[data_required()])
    product_description = TextAreaField("Product Description", validators=[data_required()])
    product_stock = IntegerField("Product Stock", validators=[data_required()])
    product_price = FloatField("Product Price", validators=[data_required()])
    product_image = StringField("Product Image URL", validators=[Optional()])
    submit = SubmitField("Add Product")
    update = SubmitField("Update Product")

class DeleteForm (FlaskForm):
    submit = SubmitField("Delete")

#Creates a context to manage the database
with app.app_context():
    #Drops all tables from the database
    #db.drop_all()

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
        user_role = None
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

            # Clearing the form data after it has been submitted
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
        address = None
        city = None
        state = None
        zip = None
        password = None
        passHash = None
        form = RegisterForm()
        # Checks if the submit button has been pressed
        # Add this debug print to see what's in the form data ------------ REMOVE LATER ------------
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
                    user = UserCredentials(user_Name = form.username.data, user_DOB = form.dob.data, user_Address = form.address.data, user_City = form.city.data, user_State = form.state.data, user_Zip = form.zip.data, user_Email = form.email.data, pass_hash = passHash)
                    session['username'] = user.user_Name  
                    session['user_role'] = user.user_Role
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

            # Clearing the form data after it has been submitted
            username = form.username.data
            form.username.data = ''
            dob = form.dob.data
            form.dob.data = ''
            address = form.address.data
            form.address.data = ''
            city = form.city.data
            form.city.data = ''
            state = form.state.data
            form.state.data = ''
            zip = form.zip.data
            form.zip.data = ''
            email = form.email.data
            form.email.data = ''
            password = form.password.data
            form.password.data = ''

        # Re-rendering the account creation page after an unsuccessful submission
        return render_template('create_acct.html', form=form, username = username, dob = dob, address = address, city = city, state = state, zip = zip, email = email, passHash = passHash)

#======================= Forgot_Password =======================#
@app.route('/Forgot_Password', methods=['POST', 'GET'])
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

        # Checks if the submit button has been pressed
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

            # Clearing the form data after it has been submitted
            username = form.username.data
            form.username.data = ''
            newpassword = form.newpassword.data
            form.newpassword.data = ''

        return render_template('forgotpw.html', form=form, username=username, passHash=passHash)


#======================= Homepage =======================#
@app.route('/Homepage')
@logged_in_required()
def homepage():
    return render_template('homepage.html')
    
#======================= Parts =======================#
@app.route('/Homepage/Parts')
@logged_in_required()
def parts():
    return render_template('parts.html')
    
#======================= Cart =======================#
@app.route('/Homepage/Cart')
@logged_in_required()
def cart():
    return render_template('cart.html')
    
#======================= Orders =======================#
@app.route('/Homepage/Orders')
@logged_in_required()
def orders():
    return render_template('orders.html')
    
#======================= Account =======================#
@app.route('/Homepage/Account')
@logged_in_required()
def account():
    return render_template('account.html')

#======================= Admin =======================#
@app.route('/Homepage/Admin', methods=['POST', 'GET'])
@admin_required()
def admin():
    user_id = None
    new_role = None
    product_name = None
    product_brand = None
    product_type = None
    product_description = None
    product_stock = None
    product_price = None
    product_image = None
    user_form = AdminUserForm()
    product_form = AdminProductForm()
    delete_form = DeleteForm()

    # Handle User Role Updates
    if user_form.validate_on_submit():
        user = UserCredentials.query.filter_by(user_ID=user_form.user_id.data).first()
        if user:
            if user.user_Role == user_form.new_role.data:
                flash(f"User ID {user_form.user_id.data} already has the role {user_form.new_role.data}.")
            else:
                user.user_Role = user_form.new_role.data
                db.session.commit()
                flash(f"User ID {user_form.user_id.data} role updated to {user_form.new_role.data}.")
        else:
            flash("Error: User ID not found.")

    # Handle Product Operations
    if product_form.submit.data and product_form.validate():  # Add new product
        product = Products(
            product_Name=product_form.product_name.data,
            product_Brand=product_form.product_brand.data,
            product_Type=product_form.product_type.data,
            product_Description=product_form.product_description.data,
            product_Stock=product_form.product_stock.data,
            product_Price=product_form.product_price.data,
            product_Image=product_form.product_image.data or 'default_product.png'
        )
        db.session.add(product)
        db.session.commit()
        flash(f"Product '{product_form.product_name.data}' added successfully.", "success")

    elif product_form.update.data and product_form.validate():  # Update existing product
        product = Products.query.get(product_form.product_id.data)
        if product:
            product.product_Name = product_form.product_name.data
            product.product_Brand = product_form.product_brand.data
            product.product_Type = product_form.product_type.data
            product.product_Description = product_form.product_description.data
            product.product_Stock = product_form.product_stock.data
            product.product_Price = product_form.product_price.data
            product.product_Image = product_form.product_image.data or product.product_Image
            db.session.commit()
            flash(f"Product '{product_form.product_name.data}' updated successfully.", "success")
        else:
            flash("Error: Product not found.", "danger")

    # Handle Delete Operations
    if delete_form.validate_on_submit():
        if 'delete_user' in request.form:
            user_id = request.form.get('delete_user')
            user = UserCredentials.query.filter_by(user_ID=user_id).first()
            if user:
                if user.user_Role == 'root_admin':
                    flash("Cannot delete root admin account.", "danger")
                else:
                    db.session.delete(user)
                    db.session.commit()
                    flash(f"User '{user.user_Name}' deleted successfully.", "success")
            else:
                flash("Error: User not found.", "danger")
        
        elif 'delete_product' in request.form:
            product_id = request.form.get('delete_product')
            product = Products.query.filter_by(product_ID=product_id).first()
            if product:
                db.session.delete(product)
                db.session.commit()
                flash(f"Product '{product.product_Name}' deleted successfully.", "success")
            else:
                flash("Error: Product not found.", "danger")

    # Handle Edit Product Request
    if 'edit_product' in request.args:
        product_id = request.args.get('edit_product')
        product = Products.query.filter_by(product_ID=product_id).first()
        if product:
            product_form = AdminProductForm(
                product_id=product.product_ID,
                product_name=product.product_Name,
                product_brand=product.product_Brand,
                product_type=product.product_Type,
                product_description=product.product_Description,
                product_stock=product.product_Stock,
                product_price=product.product_Price,
                product_image=product.product_Image
            )
            
    user_id = user_form.user_id.data
    user_form.user_id.data = ''
    new_role = user_form.new_role.data
    user_form.new_role.data = ''
    product_name = product_form.product_name.data
    product_form.product_name.data = ''
    product_brand = product_form.product_brand.data
    product_form.product_brand.data = ''
    product_type = product_form.product_type.data
    product_form.product_type.data = ''
    product_description = product_form.product_description.data
    product_form.product_description.data = ''
    product_stock = product_form.product_stock.data
    product_form.product_stock.data = ''
    product_price = product_form.product_price.data
    product_form.product_price.data = ''
    product_image = product_form.product_image.data
    product_form.product_image.data = ''
    users = UserCredentials.query.all()
    products = Products.query.all()
    return render_template('admin.html', user_form = user_form, new_role = new_role, product_form = product_form, delete_form = delete_form, users = users, products = products)

#======================= Logout =======================#
@app.route('/logout')
@logged_in_required()
def log_out():
    session.pop('username')
    flash("You have been logged out.")
    return redirect(url_for('log_in'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8000)