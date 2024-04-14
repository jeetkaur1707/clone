from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os
# Create a Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

# Configure the database URL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:krishna@localhost:5432/test'

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize the login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Define the route name for the login page

# Define the User model using SQLAlchemy
class User(db.Model, UserMixin):
    __tablename__ = 'users'  # Table name

    id = db.Column(db.Integer, primary_key=True)  # Primary key
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    def __repr__(self):
        return f"<User {self.username}>"
    
class Profile(db.Model):
    __tablename__ = 'profiles'  # Table name

    id = db.Column(db.Integer, primary_key=True)  # Primary key
    username = db.Column(db.String(50), db.ForeignKey('users.username'), nullable=False)  # Foreign key to the User table
    post = db.Column(db.String(1000), nullable=True)  # User's post (e.g., a status update)
    follower = db.Column(db.Integer, nullable=False, default=0)  # Number of followers
    following = db.Column(db.Integer, nullable=False, default=0)  # Number of users the current user is following
    nickname = db.Column(db.String(50), nullable=True)  # User's nickname
    bio = db.Column(db.String(200), nullable=True)  # User's bio

    # Relationship to the User model
    user = db.relationship('User', backref=db.backref('profile', uselist=False))

    def __repr__(self):
        return f"<Profile {self.user_id}>"


# Create the tables in the database
with app.app_context():
    db.create_all()

# Define the user loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route for home (login) page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve the username and password from the form
        username = request.form.get('username')
        password = request.form.get('password')

        # Query the database for the user
        user = User.query.filter_by(username=username).first()

        # Check the user's credentials
        if user and check_password_hash(user.password, password):
            # Log the user in if credentials match
            login_user(user)
            flash('Logged in successfully!', 'success')
            return  redirect(url_for('profile'))  # Redirect to the dashboard
        
        # If login failed, display an error message
        flash('Invalid username or password.', 'danger')
    
    # Render the login form template
    return render_template('login.html')

# Route to handle user registration (signup)
@app.route('/hello', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Retrieve form data
        email = request.form.get('email')
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username is unique
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('signup'))

        # Hash the password for security
        hashed_password = generate_password_hash(password)

        # Create a new User instance with the provided data
        new_user = User(email=email, name=name, username=username, password=hashed_password)

        # Add the new user to the session and commit the transaction
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    # Render the signup form template
    return render_template('hello.html')

# Route to handle user login form (API endpoint)
@app.route('/login-form', methods=['POST'])
def login_form():
    # Retrieve the username and password from the form data
    username = request.form.get('username')
    password = request.form.get('password')

    # Query the database for the user
    user = User.query.filter_by(username=username).first()

    # Print the username and password to the console for debugging
    print(f"Username: {username}")
    print(f"Password: {password}")

    # Check if the user exists and the password matches
    if user and check_password_hash(user.password, password):
        # Log the user in if successful and return a success message
        login_user(user)
        return  redirect(url_for('profile'))
    else:
        # If not successful, return an error message
        return jsonify({"message": "Invalid username or password"})
    

# Route to handle form submissions
@app.route('/submit-form', methods=['POST'])
def submit_form():
    # Retrieve form data
    email = request.form.get('email')
    name = request.form.get('name')
    username = request.form.get('username')
    password = request.form.get('password')

    # Hash the password for security
    hashed_password = generate_password_hash(password)
    
    # Create a new User instance with the hashed password
    new_user = User(email=email, name=name, username=username, password=hashed_password)

    # Add the new user to the session and commit
    db.session.add(new_user)
    db.session.commit()

    # Create a folder in the static directory for the new user
    static_folder_path = os.path.join(app.static_folder, username)
    print(static_folder_path)
    if not os.path.exists(static_folder_path):
        os.makedirs(static_folder_path)

    # Return a success response
    return """
    <h1>Form Submission Successful!</h1>
    <p>Email: {email}</p>
    <p>Name: {name}</p>
    <p>Username: {username}</p>
    """.format(email=email, name=name, username=username)

# Route for user logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

# Route for user dashboard (protected)
@app.route('/dashboard')
@login_required
def dashboard():
    return f"<h1>Welcome, {current_user.name}!</h1>"



# # Route for user dashboard (protected)
# @app.route('/profile')
# def profile():
#     user_profile = current_user.profile
#     return render_template('profile.html', user=current_user, profile=user_profile)
@app.route('/profile')
def profile():
    # Query the database for the user's profile
    user_profile = Profile.query.filter_by(username=current_user.username).first()
    
    # If the profile is not found, set default values
    if user_profile is None:
        user_profile = Profile(
            username=current_user.username,
            post=0,
            follower=0,
            following=0,
            nickname='',
            bio=''
        )
    
    # Render the template with the user and profile information
    return render_template('profile.html', user=current_user, profile=user_profile)



# Route for user dashboard (protected)
@app.route('/home')
def home():
    user_profile = Profile.query.filter_by(username=current_user.username).first()
    
    # If the profile is not found, set default values
    if user_profile is None:
        user_profile = Profile(
            username=current_user.username,
            post=0,
            follower=0,
            following=0,
            nickname=' ',
            bio=''
        )
    return render_template('home.html',user=current_user, profile=user_profile)

# Route for user dashboard (protected)
@app.route('/explore')
def explore():
    return render_template('explore.html')


@app.route('/reels')
def reels():
    return render_template('reels.html')


@app.route('/messages')
def messages():
    return "This is not available."
# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
