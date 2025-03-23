from flask import Flask, render_template, redirect, url_for, flash, session, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
from bcrypt import hashpw, gensalt, checkpw
from flask_socketio import SocketIO
import google.generativeai as genai
import secrets,re
import random



# Import AI model
from model import generate_output

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Flask-Migrate initialization
DB_NAME = 'site.db'
mail = Mail(app)
# Initialize OAuth
oauth = OAuth(app)
socketio = SocketIO(app, cors_allowed_origins="*")


# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)  # Token for password reset
    is_oauth_user = db.Column(db.Boolean, nullable=False,default=False)  # Flag for OAuth users

# Initialize Database
with app.app_context():
    db.create_all()

google = oauth.register(
    name='google',
    client_id='1017871640725-1p8f876dlv8diob659llingqhmubvth2.apps.googleusercontent.com',
    client_secret='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',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={
        'scope': 'openid email profile',
    }
)
# Configure Gemini API
genai.configure(api_key='AIzaSyDiF3G98dWgoXvOo0FIGI4OgVxVxhpFU7U')  # Replace with your Gemini API key
model = genai.GenerativeModel(model_name="gemini-1.5-flash")  # Use the Gemini Pro model

# Store conversation history
conversation_history = []

@app.route('/interview', methods=['POST'])
def interview():
    role = request.form.get('role')
    experience = request.form.get('experience')
    interviewer = request.form.get('interviewer')
    
    # Handle the data or pass it to the AI logic
    print(f"Role: {role}, Experience: {experience}, Interviewer: {interviewer}")
    
    return render_template('interview.html', role=role, experience=experience, interviewer=interviewer)


# WebSocket to handle AI interaction
@socketio.on('start_interview')
def handle_start_interview():
    # Start the interview with a default question
    initial_question = "Hello! Can you tell me a little about yourself?"
    conversation_history.append({'role': 'ai', 'content': initial_question})
    socketio.emit('ai_question', {'question': initial_question})

@socketio.on('user_response')
def handle_user_response(data):
    user_answer = data['answer']
    conversation_history.append({'role': 'user', 'content': user_answer})

    # Generate the next question using Gemini
    prompt = f"You are an AI interviewer. Based on this answer: '{user_answer}', ask a follow-up question.Ask it techically for jobs related to software development engineer based on concepts related to user mentioned skills conceptually make that question simple and effective if user doesn't answer or says i don't know go to the next next"
    response = model.generate_content(prompt)
    next_question = response.text

    conversation_history.append({'role': 'ai', 'content': next_question})
    socketio.emit('ai_question', {'question': next_question})


@app.route('/google-login')
def google_login():
    redirect_uri= url_for('google_authorize', _external=True)
    print(f"Redirect URI: {redirect_uri}")  # Debug log
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/google-authorize')
def google_authorize():
    try:
        token = oauth.google.authorize_access_token()
        if not token:
            flash('Google login failed. Please try again.', 'danger')
            return redirect(url_for('login'))
        
        user_info = oauth.google.get('userinfo').json()
        email = user_info['email']
        name = user_info.get('name')
        
        if not email:
            flash('Failed to retrieve email from Google. Please try again.', 'danger')
            return redirect(url_for('login'))
        
        # Check if the user already exists
        user = User.query.filter_by(email=email).first()
        
        if user:
            if user.is_oauth_user:
                # Log in the OAuth user
                session['user_id'] = user.id
                flash('Welcome back! Google Login successful.', 'success')
                return redirect(url_for('dashboard'))
            else:
                # User signed up manually, redirect to login
                flash('This email is already registered with a password. Please log in manually.', 'warning')
                return redirect(url_for('login'))
        
        # Create a new user for Google sign-in
        user = User(username=name, email=email, password=None, is_oauth_user=True)
        db.session.add(user)
        db.session.commit()

        # Log in the new user
        session['user_id'] = user.id
        flash('Google Login successful!', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        flash('Google login failed or was denied. Please try again.', 'danger')
        return redirect(url_for('signup'))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        otp = random.randint(100000, 999999)

        # Password policy regex
        password_policy = re.compile(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        )

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))
        
        if not password_policy.match(password):
            flash(
                'Password must be at least 8 characters long, include at least one uppercase letter, one lowercase letter, one number, and one special character.',
                'danger'
            )
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists! Please use a different email address.', 'danger')
            return redirect(url_for('signup'))
        
        # Hash the password before storing it in the session
        hashed_password = hashpw(password.encode('utf-8'), gensalt())

        # Set session variables for signup verification
        session['username'] = username
        session['signup_email'] = email
        session['signup_password'] = hashed_password.decode('utf-8')
        session['signup_otp'] = otp
        session['is_login_verification'] = False  # Indicate it's a signup verification

        # Send OTP email
        msg = Message('Your Signup OTP', sender='benarjeenalluri07@gmail.com', recipients=[email])
        msg.body = f'Your OTP is: {otp}. Please enter it to verify your account.'
        mail.send(msg)

        return redirect(url_for('verify_otp'))

    return render_template('signup.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        stored_otp = session.get('signup_otp')

        if entered_otp == str(stored_otp):
            if session.get('is_login_verification'):
                # Handle login verification
                email = session.get('signup_email')
                user = User.query.filter_by(email=email).first()

                if user:
                    # Log the user in
                    session['user_id'] = user.id

                    # Clear session data used for login verification
                    del session['signup_email']
                    del session['signup_password']
                    del session['signup_otp']
                    del session['is_login_verification']

                    flash('Login verification successful!', 'success')
                    return redirect(url_for('dashboard'))
            else:
                # Handle signup verification
                username = session.get('username')
                email = session.get('signup_email')
                password = session.get('signup_password')

                if username and email and password:
                    # Create a new user
                    user = User(username=username, email=email, password=password)
                    db.session.add(user)
                    db.session.commit()

                    # Log the new user in
                    session['user_id'] = user.id

                    # Clear session data used for signup verification
                    # Clear session data
                    del session['username']
                    del session['signup_email']
                    del session['signup_password']
                    del session['signup_otp']
                    del session['is_login_verification']
                

                    flash('Signup verification successful!', 'success')
                    return redirect(url_for('dashboard'))

        flash('Invalid OTP. Please try again.', 'danger')
        return redirect(url_for('verify_otp'))

    return render_template('otp.html')  # Use the same template for both login and signup OTP verification


#login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        otp = random.randint(100000, 999999)

        # Check if the user exists
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('No account found with this email. Please sign up first.', 'danger')
            return redirect(url_for('signup'))

        # If the user is an OAuth user, prompt them to log in via Google
        if user.is_oauth_user:
            flash('This email is linked to a Google account. Please log in using Google.', 'info')
            return redirect(url_for('signup'))

        # For non-OAuth users, verify the password
        if not checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            flash('Invalid credentials. Please try again.', 'danger')
            return redirect(url_for('login'))

        # Set session variables for login verification
        session['signup_email'] = email
        session['signup_password'] = password
        session['signup_otp'] = otp
        session['is_login_verification'] = True  # Indicate it's a login verification

        # Send OTP email
        msg = Message('Your Login OTP', sender='benarjeenalluri07@gmail.com', recipients=[email])
        msg.body = f'Your OTP is: {otp}. Please enter it to verify your account.'
        mail.send(msg)

        return redirect(url_for('verify_otp'))


    return render_template('loginpage2.html')


@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    email = session.get('signup_email')
    if not email:
        flash('Session expired. Please restart the process.', 'danger')
        return redirect(url_for('signup'))

    otp = random.randint(100000, 999999)
    session['signup_otp'] = otp

    msg = Message('Your OTP', sender='benarjeenalluri07@gmail.com', recipients=[email])
    msg.body = f'Your new OTP is: {otp}. Please enter it to verify your account.'
    mail.send(msg)

    flash('A new OTP has been sent to your email.', 'info')

    # Redirect based on verification context
    if session.get('is_login_verification'):
        return redirect(url_for('verify_otp'))
    else:
        return redirect(url_for('verify_otp'))




# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('Dashboard.html')


@app.route('/resources')
def resources():
    return render_template('resources.html')

@app.route('/software')
def software():
    return render_template('software.html')

@app.route('/datascience')
def datascience():
    return render_template('datascience.html')

@app.route('/dataanalyst')
def dataanalyst():
    return render_template('dataanalyst.html')

@app.route('/python')
def python():
    return render_template('pythondeveloper.html')

@app.route('/qa')
def qa():
    return render_template('qaanalyst.html')

@app.route('/backend')
def backend():
    return render_template('backend.html')

@app.route('/behavioral')
def behavioral():
    return render_template('behavioral.html')

@app.route('/frontend')
def frontend():
    return render_template('frontend.html')

@app.route('/fullstack')
def fullstack():
    return render_template('fullstack.html')

@app.route('/uiux')
def uiux():
    return render_template('uiux.html')




# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a unique token
            reset_token = secrets.token_urlsafe(16)
            user.reset_token = reset_token
            db.session.commit()

            # Generate reset URL
            reset_url = url_for('reset_password', token=reset_token, _external=True)

            # Send reset email
            msg = Message('Password Reset Request', sender='benarjeenalluri07@gmail.com', recipients=[email])
            msg.body = f'Please click the link to reset your password: {reset_url}'
            mail.send(msg)

            flash('A password reset link has been sent to your email.', 'info')
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

# Reset Password Route
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new-password']
        confirm_password = request.form['confirm-password']

        # Password policy regex
        password_policy = re.compile(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        )

        # Check if passwords match
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        # Check if password meets the policy
        if not password_policy.match(new_password):
            flash(
                'Password must be at least 8 characters long, include at least one uppercase letter, one lowercase letter, one number, and one special character.',
                'danger'
            )
            return redirect(url_for('reset_password', token=token))
        
         # Hash the new password
        hashed_password = hashpw(new_password.encode('utf-8'), gensalt())

        # Update the user's password and clear the token
        user.password = hashed_password.decode('utf-8')
        user.reset_token = None  # Clear the token after reset
        db.session.commit()

        flash('Your password has been reset successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)



if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, transports=['websocket'])



