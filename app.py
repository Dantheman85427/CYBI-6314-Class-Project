from flask import Flask, render_template, flash, redirect, url_for, session, jsonify, request
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy #pip install Flask-SQLAlchemy
from pathlib import Path
from argon2 import PasswordHasher       #pip install argon2-cffi
from flask_wtf import FlaskForm         #pip install flask-wtf
import stripe, os, string
from sqlalchemy import Text
from wtforms import StringField, SubmitField, EmailField, DateField, IntegerField, FloatField, TextAreaField, SelectField, FileField
from wtforms.validators import data_required, ValidationError, Optional
from functools import wraps
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-insecure-key-change-in-production')
# Read from file
stripe_keys = {
    "secret_key": os.environ["SK_TEST"],
    "publishable_key": os.environ["PK_TEST"],
}
stripe.api_key = stripe_keys["secret_key"]

#Configuring the Database location
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f"sqlite:///{Path(__file__).parent / './Databases/userAccounts.db'}")
app.config['UPLOAD_FOLDER'] = 'static/images/'
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
        admin_password = os.getenv('ADMIN_PASSWORD')
        if not admin_password:
            # Generate a random password if not set in your environment
            import secrets
            admin_password = secrets.token_urlsafe(16)
            print(f"ADMIN_PASSWORD not set in .env file!")
            print(f"Generated random admin password: {admin_password}")
            print(f"Please add ADMIN_PASSWORD {admin_password} to your .env file")

        # Hash the password (Argon2 will handle salting internally)
        adminPassHash = generateHash(admin_password)
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
    userid = IntegerField("User ID", validators=[Optional()])  # For editing existing users
    username = StringField("Username:", validators=[data_required()])
    email = EmailField("Email: ", validators=[data_required()])
    address = StringField("Address: ", validators=[data_required()])
    city = StringField("City: ", validators=[data_required()])
    state = StringField("State: ", validators=[data_required()])
    zip = StringField("Zip Code: ", validators=[data_required()])
    password = StringField("Password: ", validators=[Optional(), validatePassword])
    submit = SubmitField("Update Account")
    update = SubmitField("Update Account")  # For when editing

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
    product_image = FileField("Product Image", validators=[Optional()])
    submit = SubmitField("Add Product")
    update = SubmitField("Update Product")

#======= Cart and Orders =======#

class Cart(db.Model):
    __tablename__ = 'cart'

    cart_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user_credentials.user_ID'), unique=True)

    created_at = db.Column(db.DateTime, default=datetime.now)
    items = db.relationship("CartItem", backref="cart", cascade="all, delete")

class CartItem(db.Model):
    __tablename__ = 'cart_item'

    item_id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.cart_id'))
    product_id = db.Column(db.Integer, db.ForeignKey('products.product_ID'))
    quantity = db.Column(db.Integer, default=1)

    # Get product info easily
    product = db.relationship("Products")

class Orders(db.Model):
    __tablename__ = 'orders'

    order_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user_credentials.user_ID'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    total_price = db.Column(db.Float, default=0.0)

    items = db.relationship("OrderItem", backref="order", cascade="all, delete")

class OrderItem(db.Model):
    __tablename__ = 'order_item'

    item_id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.order_id'))
    product_id = db.Column(db.Integer, db.ForeignKey('products.product_ID'))
    quantity = db.Column(db.Integer, default=1)
    price_each = db.Column(db.Float)

    product = db.relationship("Products")



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
                        cart = Cart.query.filter_by(user_id=user.user_ID).first()
                        if not cart or len(cart.items) == 0:
                            print("DEBUG: Cart is empty")  # Debug line
                            session['cart_length'] = 0
                        else: 
                            print("DEBUG: Cart has " + str(len(cart.items)))
                            session['cart_length'] = len(cart.items)
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

        if form.validate_on_submit():
            existing_username = UserCredentials.query.filter_by(user_Name=form.username.data).first()
            existing_email = UserCredentials.query.filter_by(user_Email=form.email.data).first()
            if existing_username is None:
                if existing_email is None:
                    passHash = generateHash(form.password.data)
                    user = UserCredentials(
                        user_Name=form.username.data, 
                        user_DOB=form.dob.data, 
                        user_Address=form.address.data, 
                        user_City=form.city.data, 
                        user_State=form.state.data, 
                        user_Zip=form.zip.data, 
                        user_Email=form.email.data, 
                        pass_hash=passHash
                    )
                    db.session.add(user)
                    db.session.commit()
                    
                    # CREATE CART FOR NEW USER
                    user_id = user.user_ID
                    cart = Cart(user_id=user_id)
                    db.session.add(cart)
                    db.session.commit()
                    
                    session['username'] = user.user_Name  
                    session['user_id'] = user.user_ID
                    session['cart_length'] = 0

                    flash("Account created successfully! Welcome, " + session.get('username') + "!")
                    return redirect(url_for('homepage'))
                else:
                    flash("Error: Email already in use.")
            else:
                flash("Error: Username already in use.")

        return render_template('create_acct.html', form=form, username=username, dob=dob, address=address, city=city, state=state, zip=zip, email=email, passHash=passHash)
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
@app.route('/Homepage/Parts/<category>')
@logged_in_required()
def parts(category=None):
    # Map URL categories to database product types
    category_mapping = {
        'cpus': 'CPU',
        'gpus': 'GPU', 
        'memory': 'RAM',
        'motherboards': 'Motherboard',
        'storage': 'Storage',
        'power-supplies': 'PSU',
        'cases': 'Case',
        'cooling': 'Cooling',
        'accessories': 'Other'
    }
    
    # Base query
    query = Products.query
    
    # Apply category filter if provided
    product_type = None
    if category and category in category_mapping:
        product_type = category_mapping[category]
        query = query.filter(Products.product_Type == product_type)
    
    # Get search term from request (sanitized)
    search_term = request.args.get('search', '').strip()

    # Apply search filter if provided
    if search_term:
        # Sanitize search term
        import re
        sanitized_search = re.sub(r'[^\w\s\-\.]', '', search_term)
        if sanitized_search:
            # Search in name, brand, and description using case-insensitive matching
            search_filter = db.or_(
                Products.product_Name.ilike(f'%{sanitized_search}%'),
                Products.product_Brand.ilike(f'%{sanitized_search}%'),
                Products.product_Description.ilike(f'%{sanitized_search}%'),
                Products.product_Type.ilike(f'%{sanitized_search}%'),
            )
            query = query.filter(search_filter)

    # Get brand filter from request
    brand_filter = request.args.get('brand')
    if brand_filter:
        query = query.filter(Products.product_Brand == brand_filter)
    
    # Get price filters from request
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    
    if min_price is not None and min_price > 0:
        query = query.filter(Products.product_Price >= min_price)
    
    if max_price is not None and max_price > 0:
        query = query.filter(Products.product_Price <= max_price)
    
    # Execute query
    products = query.all()
    
    # Get available brands for the current category
    brands_query = Products.query
    if product_type:
        brands_query = brands_query.filter(Products.product_Type == product_type)
    
    brands = list(set([p.product_Brand for p in brands_query.all() if p.product_Brand]))
    brands.sort()
    
    # Get category name for display
    category_name = product_type if product_type else None
    
    return render_template('parts.html', 
                         products=products,
                         brands=brands,
                         category=category,
                         category_name=category_name,
                         brand_filter=brand_filter,
                         min_price=min_price or 0,
                         max_price=max_price,
                         search_term=search_term)


#======================= Cart =======================#

@app.route('/add_to_cart/<int:product_id>')
@logged_in_required()
def add_to_cart(product_id):
    user_id = session['user_id']

    # Check if user already has a cart
    cart = Cart.query.filter_by(user_id=user_id).first()

    # If no cart exists, create one
    if not cart:
        cart = Cart(user_id=user_id)
        db.session.add(cart)
        db.session.commit()

    # Check if product already in cart
    item = CartItem.query.filter_by(cart_id=cart.cart_id, product_id=product_id).first()

    if item:
        item.quantity += 1
    else:
        item = CartItem(cart_id=cart.cart_id, product_id=product_id, quantity=1)
        db.session.add(item)

    db.session.commit()
    session['cart_length'] = len(cart.items)
    flash("Item added to cart!")
    return redirect(request.referrer)

#======================= Cart =======================#
@app.route('/Homepage/Cart')
@logged_in_required()
def cart():
    user_id = session['user_id']
    print(f"DEBUG: User ID: {user_id}")  # Debug line
    
    cart = Cart.query.filter_by(user_id=user_id).first()
    print(f"DEBUG: Cart found: {cart}")  # Debug line
    
    if not cart or len(cart.items) == 0:
        print("DEBUG: Cart is empty")  # Debug line
        return render_template('cart.html', items=[], total=0)

    total = sum(item.product.product_Price * item.quantity for item in cart.items)
    print(f"DEBUG: Cart items: {len(cart.items)}, Total: {total}")  # Debug line

    return render_template('cart.html', items=cart.items, total=total, key=stripe_keys['publishable_key'])
#======================= Cart Alteration =======================#

@app.route('/cart/increase/<int:item_id>')
@logged_in_required()
def increase_quantity(item_id):
    # Increases quantity by 1
    user_id = session['user_id']
    
    # Find the cart item

    cart_item = CartItem.query.get(item_id)

    if not cart_item:
        flash('Item not found!')
        return redirect(url_for('cart'))
    
    # Security checks
    if cart_item.cart.user_id != user_id:
        flash('Unauthorized action')
        return redirect(url_for('cart'))
    cart_item.quantity += 1

    cart = Cart.query.filter_by(user_id=user_id).first()
    session['cart_length'] = len(cart.items)

    db.session.commit()
    flash('Quantity increased!')
    return redirect(url_for('cart'))

# ==== Decrease ==== #
@app.route('/cart/decrease/<int:item_id>')
@logged_in_required()
def decrease_quantity(item_id):
    user_id = session['user_id']
    
    # Find the cart item
    cart_item = CartItem.query.get(item_id)
    
    if not cart_item:
        flash('Item not found')
        return redirect(url_for('cart'))
    
    # Security check: make sure this item belongs to the current user's cart
    if cart_item.cart.user_id != user_id:
        flash('Unauthorized action')
        return redirect(url_for('cart'))
    
    # Decrease quantity
    if cart_item.quantity > 1:
        cart_item.quantity -= 1
        db.session.commit()
        flash('Quantity decreased')
    else:
        # If quantity is 1, remove the item entirely
        db.session.delete(cart_item)
        db.session.commit()
        flash('Item removed from cart')

    cart = Cart.query.filter_by(user_id=user_id).first()
    session['cart_length'] = len(cart.items)

    return redirect(url_for('cart'))

# ==== Remove ==== #
@app.route('/cart/remove/<int:item_id>')
@logged_in_required()
def remove_item(item_id):
    user_id = session['user_id']
    
    cart_item = CartItem.query.get(item_id)
    
    if not cart_item:
        flash('Item not found')
        return redirect(url_for('cart'))
    
    # Security check
    if cart_item.cart.user_id != user_id:
        flash('Unauthorized action')
        return redirect(url_for('cart'))
    
    product_name = cart_item.product.product_Name
    db.session.delete(cart_item)
    db.session.commit()

    cart = Cart.query.filter_by(user_id=user_id).first()
    session['cart_length'] = len(cart.items)

    flash(f'{product_name} removed from cart')
    
    return redirect(url_for('cart'))
# ==== Empty cart ==== #
@app.route('/cart/empty')
@logged_in_required()
def empty_cart():

    user_id = session['user_id']
    
    cart = Cart.query.filter_by(user_id=user_id).first()
    
    if cart:
        # Delete all cart items
        CartItem.query.filter_by(cart_id=cart.cart_id).delete()
        db.session.commit()
        session['cart_length'] = 0
        flash('Cart emptied')
    
    return redirect(url_for('cart'))
#======================= Cart --> Orders =======================#
@app.route('/checkout', methods=['POST'])
@logged_in_required()
def checkout():
    try: 
        user_id = session['user_id']
        cart = Cart.query.filter_by(user_id=user_id).first()

        if not cart or len(cart.items) == 0:
            flash("Cart is empty.")
            return redirect(url_for('cart'))
        # Move each cart item to OrderItem
        for item in cart.items:
            product = Products.query.get(item.product_id)
            if product.product_Stock < item.quantity:
                flash(f"We apologize! We only have {product.product_Stock} in stock for {product.product_Name}. Please reduce the quantity in your cart.")
                db.session.rollback()
                return redirect(url_for('cart'))
        line_items = []
        for item in cart.items:
            product = Products.query.get(item.product_id)
            line_items.append({
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': product.product_Name,
                        'description': f"Brand: {product.product_Brand}",
                    },
                    'unit_amount': int(product.product_Price * 100),  # Amount in cents
                },
                'quantity': item.quantity,
            })
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=line_items,
            mode='payment',
            success_url=url_for('payment_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('cart', _external=True),
            metadata={
                'user_id': str(user_id),
                'cart_id': str(cart.cart_id)
            }
        )
        return jsonify({'id': checkout_session.id})
    
    except Exception as e:
        print(f"Error creating checkout session: {e}")
        flash("An error occurred while processing your payment. Please try again.")
        return redirect(url_for('cart'))
    
@app.route('/payment_success')
@logged_in_required()
def payment_success():
    try: 
        stripe_session_id = request.args.get('session_id')
        if not stripe_session_id:
            flash('Invalid payment session.')
            return redirect(url_for('cart'))
        
        # Retrieve the Stripe session
        stripe_checkout_session = stripe.checkout.Session.retrieve(stripe_session_id)

        if stripe_checkout_session.payment_status != 'paid':
            flash('Payment was not successful.')
            return redirect(url_for('cart'))
        
        user_id = session['user_id']
        cart = Cart.query.filter_by(user_id=user_id).first()

        if not cart:
            flash("Cart not found.")
            return redirect(url_for('cart'))   
        
        # Verify the Stripe session matches our user
        if int(stripe_checkout_session.metadata.get('user_id')) != user_id:
            flash('Payment session user mismatch.')
            return redirect(url_for('cart'))

        # Create an order
        order = Orders(user_id=user_id, total_price=0.0)
        db.session.add(order)
        db.session.commit()

        total_price = 0

        # Move each cart item to OrderItem
        for item in cart.items:
            product = Products.query.get(item.product_id)
            if product.product_Stock < item.quantity:
                flash(f"We apologize! We only have {product.product_Stock} in stock for {product.product_Name}. Please reduce the quantity in your cart.")
                db.session.rollback()
                return redirect(url_for('cart'))
            
            # Decrease product stock
            product.product_Stock -= item.quantity

            order_item = OrderItem(
                order_id=order.order_id,
                product_id=item.product_id,
                quantity=item.quantity,
                price_each=item.product.product_Price
            )
            db.session.add(order_item)

            total_price += item.product.product_Price * item.quantity

        order.total_price = total_price

        # Clear cart
        CartItem.query.filter_by(cart_id=cart.cart_id).delete()
        db.session.commit()

        cart = Cart.query.filter_by(user_id=user_id).first()
        session['cart_length'] = len(cart.items)

        flash("Payment successful! Your order has been placed.")
        return redirect(url_for('orders'))
    except Exception as e:
        print(f"Error processing payment success: {e}")
        db.session.rollback() # Rollback any database changes
        flash("An error occurred while finalizing your order. Please contact support.")
        return redirect(url_for('cart'))


@app.route('/Homepage/Orders')
@logged_in_required()
def orders():
    user_id = session['user_id']
    orders = Orders.query.filter_by(user_id=user_id).order_by(Orders.created_at.desc()).all()
    return render_template('orders.html', orders=orders)

    
#======================= Account =======================#
@app.route('/Homepage/Account', methods=['POST', 'GET'])
@logged_in_required()
def account():
    form = AccountForm()
    delete_form = DeleteForm()

    current_user = UserCredentials.query.filter_by(user_Name = session.get('username')).first()
    # Handle Edit Product Request
    if 'edit_account' in request.args:
        user_id = request.args.get('edit_account')
        user = UserCredentials.query.filter_by(user_ID = user_id).first()
        if user and user.user_ID == current_user.user_ID: # User can only delete their own account
            form = AccountForm(
                userid = user.user_ID,
                username = user.user_Name,
                email = user.user_Email,
                address = user.user_Address or '',
                city = user.user_City or '',
                state = user.user_State or '',
                zip = user.user_Zip or ''
            )

    if form.validate_on_submit():
        # Checking if new username or email exists (excluding current user)
        existing_username = UserCredentials.query.filter(UserCredentials.user_Name == form.username.data, UserCredentials.user_ID != current_user.user_ID).first()
        existing_email = UserCredentials.query.filter(UserCredentials.user_Email == form.email.data, UserCredentials.user_ID != current_user.user_ID).first()
        if existing_username is None:
            if existing_email is None:

                current_user.user_Name = form.username.data
                current_user.user_Email = form.email.data
                current_user.user_Address = form.address.data
                current_user.user_City = form.city.data
                current_user.user_State = form.state.data
                current_user.user_Zip = form.zip.data

                if form.password.data:
                    current_user.pass_hash = generateHash(form.password.data)

                db.session.commit()
                session['username'] = current_user.user_Name
                session['user_id'] = current_user.user_ID
                flash("Account information updated successfully.")

                return redirect(url_for('account'))

            else: 
                flash("Error: Email already in use.")
        else: 
            flash("Error: Username already in use.")

    # Handle Delete Operations
    if delete_form.validate_on_submit() and 'delete_user' in request.form:
        user_id = request.form.get('delete_user')
        user = UserCredentials.query.filter_by(user_ID = user_id).first()
        if user and user.user_ID == current_user.user_ID:
            if user.user_Role == 'root_admin':
                flash("Cannot delete root admin account.")
            else:
                db.session.delete(user)
                db.session.commit()
                session.pop('username', None)
                session.pop('user_id', None)
                flash(f"You have successfully deleted your account, '{user.user_Name}'.")
                return redirect(url_for('log_in'))
        else:
            flash("Error: User not found.")

    return render_template('account.html', user = current_user, form = form, delete_form = delete_form)

#======================= Product Filter Form =======================#
class ProductFilterForm(FlaskForm):
    product_type = SelectField("Filter by Product Type", choices=[
        ('', 'All Products'),
        ('CPU', 'CPU'),
        ('GPU', 'GPU'),
        ('RAM', 'RAM'),
        ('Motherboard', 'Motherboard'),
        ('Storage', 'Storage'),
        ('PSU', 'Power Supply'),
        ('Case', 'Case'),
        ('Cooling', 'Cooling'),
        ('Other', 'Other')
    ], validators=[Optional()])
    submit = SubmitField("Apply Filter")


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
    filter_form = ProductFilterForm()  # Add filter form

    # Handle Product Filtering (GET request)
    selected_type = request.args.get('product_type', '')
    if selected_type:
        filter_form.product_type.data = selected_type

    # Build products query based on filter
    products_query = Products.query
    if selected_type:
        products_query = products_query.filter(Products.product_Type == selected_type)

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
        if product_form.product_image.data:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            product_path = os.path.join(app.config['UPLOAD_FOLDER'], product_form.product_type.data)
            os.makedirs(product_path, exist_ok=True)
            filename = secure_filename(product_form.product_image.data.filename)
            filepath = os.path.join(product_path, filename)
            product_form.product_image.data.save(filepath)
        else: 
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'default_product.png')
        product = Products(
            product_Name = product_form.product_name.data,
            product_Brand = product_form.product_brand.data,
            product_Type = product_form.product_type.data,
            product_Description = product_form.product_description.data,
            product_Stock = product_form.product_stock.data,
            product_Price = product_form.product_price.data,
            product_Image = filepath
        )
        db.session.add(product)
        db.session.commit()
        flash(f"Product '{product_form.product_name.data}' added successfully.", "success")
        # Clear form after successful submission
        return redirect(url_for('admin', product_type=selected_type))

    elif product_form.update.data and product_form.validate():  # Update existing product
        product = Products.query.get(product_form.product_id.data)
        if product:
            if product_form.product_image.data:
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                product_path = os.path.join(app.config['UPLOAD_FOLDER'], product_form.product_type.data)
                os.makedirs(product_path, exist_ok=True)
                filename = secure_filename(product_form.product_image.data.filename)
                filepath = os.path.join(product_path, filename)
                product_form.product_image.data.save(filepath)
            else: 
                filepath = product.product_Image  # Keep existing image if no new one
            product.product_Name = product_form.product_name.data
            product.product_Brand = product_form.product_brand.data
            product.product_Type = product_form.product_type.data
            product.product_Description = product_form.product_description.data
            product.product_Stock = product_form.product_stock.data
            product.product_Price = product_form.product_price.data
            product.product_Image = filepath
            db.session.commit()
            flash(f"Product '{product_form.product_name.data}' updated successfully.", "success")
            # Clear form after successful update
            return redirect(url_for('admin', product_type=selected_type))
        else:
            flash("Error: Product not found.", "danger")

    # Handle Delete Operations
    if delete_form.validate_on_submit():
        if 'delete_user' in request.form:
            user_id = request.form.get('delete_user')
            user = UserCredentials.query.filter_by(user_ID=user_id).first()
            if user:
                if user.user_Name == 'admin':
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
                product_id = product.product_ID,
                product_name = product.product_Name,
                product_brand = product.product_Brand,
                product_type = product.product_Type,
                product_description = product.product_Description,
                product_stock = product.product_Stock,
                product_price = product.product_Price
                # Note: product_image is handled separately in the form
            )

    # Clear form data (only if not editing)
    if not request.args.get('edit_product'):
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
    products = products_query.all()  # Use the filtered query
    
    return render_template('admin.html', 
                         user_form=user_form, 
                         product_form=product_form, 
                         delete_form=delete_form,
                         filter_form=filter_form, 
                         users=users, 
                         products=products,
                         selected_type=selected_type)

#======================= Build Guide =======================#
@app.route('/Homepage/Build_Guide')
@logged_in_required()
def build_guide():
    flash("Hello Welcome to the Build Guide! This feature is coming soon!")
    return render_template('build_guide.html')

#======================= PreBuilt_PCs =======================#
@app.route('/Homepage/PreBuilt_PCs')
@logged_in_required()
def prebuilt_pcs():
    flash("Hello Welcome to the PreBuilt_PCs! This feature is coming soon!")
    return render_template('prebuilt_pcs.html')

#======================= Compatibility_Checker =======================#
@app.route('/Homepage/Compatibility_Checker')
@logged_in_required()
def compatibility_checker():
    flash("Hello Welcome to the Compatibility_Checker! This feature is coming soon!")
    return render_template('compatibility_checker.html')

#======================= Warranty =======================#
@app.route('/Homepage/Warranty')
@logged_in_required()
def warranty():
    flash("Hello Welcome to the Warranty! This feature is coming soon!")
    return render_template('warranty.html')

#======================= Contact_Us =======================#
@app.route('/Homepage/Contact_Us')
@logged_in_required()
def contact_us():
    flash("Hello Welcome to the Contact_Us! This feature is coming soon!")
    return render_template('contact_us.html')

#======================= About_Us =======================#
@app.route('/Homepage/About_Us')
@logged_in_required()
def about_us():
    flash("Hello Welcome to the About_Us! This feature is coming soon!")
    return render_template('about_us.html')

#======================= Careers =======================#
@app.route('/Homepage/Careers')
@logged_in_required()
def careers():
    flash("Hello Welcome to the Careers! This feature is coming soon!")
    return render_template('careers.html')

#======================= Locations =======================#
@app.route('/Homepage/Locations')
@logged_in_required()
def locations():
    flash("Hello Welcome to the Locations! This feature is coming soon!")
    return render_template('locations.html')

#======================= Privacy_Policy =======================#
@app.route('/Homepage/Privacy_Policy')
@logged_in_required()
def privacy_policy():
    flash("Hello Welcome to the Privacy_Policy! This feature is coming soon!")
    return render_template('privacy_policy.html')

#======================= Logout =======================#
@app.route('/logout')
@logged_in_required()
def log_out():
    session.pop('username')
    session.pop('user_id')
    session.pop('cart', None)
    session.pop('cart_length', None)
    session.modified = True
    flash("You have been logged out.")
    return redirect(url_for('log_in'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8000)