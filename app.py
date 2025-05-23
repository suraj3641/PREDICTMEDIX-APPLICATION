import os
import re
import pickle
import jwt
import datetime
import pandas as pd
from bson import ObjectId
from flask import Flask, request, render_template, send_from_directory, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user,current_user
from flask_mail import Mail, Message
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_mail import Message


load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')

# MongoDB Configuration
client = MongoClient(os.getenv('MONGO_URI'))
db = client['insurance_auth']
users_collection = db['users']
tokens_collection = db['tokens']

# Flask-Mail Configuration (kept for password reset functionality)
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'true').lower() == 'true',
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER'),
    MAIL_DEBUG=True,
    MAIL_SUPPRESS_SEND=False
)
mail = Mail(app)

# Flask-Login Configuration
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.name = user_data.get('name', '') 
        self.email = user_data['email']
        self.mobile = user_data.get('mobile', '')
        self.is_verified = True  # Always set to True since we're skipping verification

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = users_collection.find_one({'_id': ObjectId(user_id)})
        return User(user_data) if user_data else None
    except Exception as e:
        print(f"User loader error: {e}")
        return None

# Load ML model
try:
    with open('insurancemodelf_fullfeatures.pkl', 'rb') as f:
        model = pickle.load(f)
except Exception as e:
    print(f"Model loading error: {e}")
    model = None

# Helper Functions
def generate_token(user_id, expiration=3600):
    return jwt.encode({
        'user_id': str(user_id),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration)
    }, app.secret_key, algorithm='HS256')

def send_reset_email(email, token):
    try:
        url = url_for('reset_password', token=token, _external=True)
        msg = Message("Reset Your Password", recipients=[email])
        msg.body = f"Click to reset your password: {url}"
        mail.send(msg)
    except Exception as e:
        print(f"Reset Email Error: {e}")

def validate_mobile_number(number):
    return re.match(r'^[6-9]\d{9}$', number)

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated: 
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        mobile = request.form['mobile']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if not all([name, email, mobile, password, confirm]):
            flash('All fields required!', 'danger')
            return redirect(url_for('signup'))

        if password != confirm:
            flash('Passwords dont match.', 'danger')
            return redirect(url_for('signup'))

        if not validate_mobile_number(mobile):
            flash('Invalid mobile number.', 'danger')
            return redirect(url_for('signup'))

        if users_collection.find_one({'email': email}) or users_collection.find_one({'mobile': mobile}):
            flash('Email or Mobile already exists.', 'danger')
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password)
        user = {
            'name': name,
            'email': email,
            'mobile': mobile,
            'password': hashed_pw,
            'is_verified': True,  # Automatically verified
            'created_at': datetime.datetime.utcnow()
        }
        result = users_collection.insert_one(user)
        
        # Immediately log the user in after signup
        login_user(User(user), remember=True)
        flash('Signup successful! You are now logged in.', 'success')
        return redirect(url_for('home'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = bool(request.form.get('remember'))

        user_data = users_collection.find_one({'email': email})
        if not user_data or not check_password_hash(user_data['password'], password):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

        # No email verification check anymore
        login_user(User(user_data), remember=remember)
        # flash('Logged in successfully!', 'success') 
        return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    # flash('logout successfully','success')
    return redirect(url_for('home'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user_data = users_collection.find_one({'email': email})
        if user_data:
            token = generate_token(user_data['_id'], expiration=3600)
            tokens_collection.insert_one({
                'user_id': user_data['_id'],
                'token': token,
                'token_type': 'password_reset',
                'created_at': datetime.datetime.utcnow(),
                'expires_at': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            })
            send_reset_email(email, token)

        flash('If your email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        user_id = payload['user_id']

        token_data = tokens_collection.find_one({
            'user_id': ObjectId(user_id),
            'token': token,
            'token_type': 'password_reset',
            'expires_at': {'$gt': datetime.datetime.utcnow()}
        })

        if not token_data:
            flash('Invalid or expired reset link.', 'danger')
            return redirect(url_for('forgot_password'))

        if request.method == 'POST':
            pw = request.form['password']
            confirm = request.form['confirm_password']
            if pw != confirm:
                flash('Passwords do not match.', 'danger')
                return redirect(url_for('reset_password', token=token))

            hashed_pw = generate_password_hash(pw)
            users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': {'password': hashed_pw}})
            tokens_collection.delete_one({'_id': token_data['_id']})
            flash('Password updated! You can login now.', 'success')
            return redirect(url_for('login'))

        return render_template('reset_password.html', token=token)

    except jwt.ExpiredSignatureError:
        flash('Reset link expired.', 'danger')
    except Exception:
        flash('Invalid reset link.', 'danger')
    return redirect(url_for('forgot_password'))

@app.route('/about')
# @login_required
def about():
    return render_template('about.html')

@app.route('/contact')
# @login_required
def contact():
    return render_template('contact.html')

@app.route('/resumes/<filename>')
# @login_required
def download_resume(filename):
    os.makedirs('resumes', exist_ok=True)
    return send_from_directory('resumes', filename, as_attachment=True)

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    try:
        if not model:
            return render_template('index.html', prediction_text="Model not loaded. Contact admin.")

        data = {
            'age': int(request.form['age']),
            'sex': 1 if request.form['sex'] == 'male' else 0,
            'bmi': float(request.form['bmi']),
            'children': int(request.form['children']),
            'smoker': 1 if request.form['smoker'] == 'yes' else 0,
            'region': {'northwest': 0, 'northeast': 1, 'southeast': 2, 'southwest': 3}[request.form['region']]
        }

        df = pd.DataFrame([data])
        prediction = model.predict(df)[0]
        return render_template('index.html', prediction_text=f'Predicted Insurance Charges: ${prediction:,.2f}')

    except Exception as e:
        return render_template('index.html', prediction_text=f'Error: {str(e)}')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)