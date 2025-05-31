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
from flask import Flask, render_template, request, send_file
from xhtml2pdf import pisa
from flask import make_response
import io
import shap



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




# Routes ============>


@app.route('/')
def home():
    return render_template('index.html')

# signup Routes========>
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




#  login Routes============>
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





# logout Routes
@app.route('/logout')
@login_required
def logout():
    logout_user()
    # flash('logout successfully','success')
    return redirect(url_for('home'))


# forgot-password==========>
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




# reset-password======>
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





def generate_health_tips(data):
    tips = []

    # BMI Tips
    if data['bmi'] < 18.5:
        tips.append("आपका BMI कम है। पोषक आहार लीजिए और वजन बढ़ाइए। (Your BMI is low. Eat nutritious food and gain weight.)")
    elif 18.5 <= data['bmi'] < 25:
        tips.append("आपका BMI सामान्य है। इसी तरह स्वस्थ रहें। (Your BMI is normal. Keep maintaining your good health.)")
    elif 25 <= data['bmi'] < 30:
        tips.append("आपका BMI थोड़ा ज्यादा है। हल्का व्यायाम शुरू करें। (Your BMI is slightly high. Start light exercise.)")
        tips.append("मीठे और तले-भुने भोजन से बचें। (Avoid sugary and fried foods.)")
    else:
        tips.append("आपका BMI बहुत ज्यादा है। वजन कम करने की कोशिश करें। (Your BMI is very high. Try to lose weight.)")
        tips.append("रोजाना 30 मिनट वॉक या योग अपनाएं। (Do a 30-minute walk or yoga daily.)")

    # Smoking Tips
    if data['smoker'] == 'yes':
        tips.append("धूम्रपान छोड़ें, इससे आपकी सेहत और बीमा खर्च दोनों सुधर सकते हैं। (Quit smoking to improve your health and reduce insurance costs.)")
        tips.append("निकोटीन गम या परामर्श से मदद लें। (Seek help through nicotine gum or counseling.)")
    else:
        tips.append("आप धूम्रपान नहीं करते, यह बहुत अच्छी बात है! (It's great that you do not smoke!)")

    # Age Tips
    if data['age'] >= 45:
        tips.append("इस उम्र में नियमित चेकअप जरूरी है। (At this age, regular health checkups are essential.)")
        tips.append("दिल की सेहत और रक्तचाप पर नजर रखें। (Monitor your heart health and blood pressure.)")
    elif data['age'] < 18:
        tips.append("आप जवान हैं, संतुलित आहार और क्रियाकलापी गतिविधियां जरूरी हैं। (You are young; balanced diet and active lifestyle are important.)")
        tips.append("खेल-कूद और पढ़ाई में संतुलन बनाएं। (Balance sports and academics.)")

    # Gender Tips
    if data['sex'] == 'female':
        tips.append("महिलाओं के लिए कैल्शियम और आयरन जरूरी है। (Calcium and iron are important for women.)")
        tips.append("हर महीने स्वास्थ्य पर ध्यान दें। (Pay attention to your health each month.)")
    elif data['sex'] == 'male':
        tips.append("पुरुषों को दिल की सेहत का ख्याल रखना चाहिए। (Men should take care of heart health.)")
        tips.append("तनाव कम करने की कोशिश करें। (Try to reduce stress.)")

    # Children Tips
    if data['children'] > 2:
        tips.append(f"आपके {data['children']} बच्चे हैं। परिवार की सेहत का ध्यान रखें। (You have {data['children']} children. Take care of your family's health.)")
        tips.append("बच्चों को टीकाकरण और संतुलित आहार जरूर दें। (Ensure your children receive vaccinations and a balanced diet.)")

    # Region Tips
    region_tips = {
        'northeast': "पूर्वोत्तर क्षेत्र में मौसमी सब्जियाँ और नियमित वॉक लाभकारी हैं। (In the northeast, seasonal vegetables and regular walks are beneficial.)",
        'northwest': "उत्तरपश्चिम में गर्मियों में पानी की मात्रा बढ़ाएं। (In the northwest, increase water intake during summers.)",
        'southeast': "दक्षिण-पूर्व में अधिक नमीयुक्त मौसम से बचने की कोशिश करें। (In the southeast, try to avoid high humidity.)",
        'southwest': "दक्षिण-पश्चिम में धूप से बचाव के उपाय करें। (In the southwest, take precautions against sun exposure.)"
    }
    region_tip = region_tips.get(data['region'], "")
    if region_tip:
        tips.append(region_tip)

    # Additional General Health Tips
    tips.append("रोजाना कम से कम 7-8 घंटे की नींद लें। (Get at least 7-8 hours of sleep every day.)")
    tips.append("हर दिन 8-10 गिलास पानी पिएं। (Drink 8–10 glasses of water daily.)")
    tips.append("हर दिन कुछ समय धूप में बिताएं ताकि विटामिन D मिले। (Spend some time in sunlight for Vitamin D.)")
    tips.append("तनाव से बचें, ध्यान या योग अपनाएं। (Avoid stress, practice meditation or yoga.)")
    tips.append("अपने खान-पान में फल, सब्ज़ियाँ और फाइबर शामिल करें। (Include fruits, vegetables, and fiber in your diet.)")

    return tips



@app.route('/predict', methods=['POST'])
@login_required
def predict():
    try:
        if model is None:
            return render_template('index.html', prediction_text="Model not loaded. Contact admin.")

        # 🔹 Extract form data from the user
        form_data = {
            'name': current_user.name,
            'age': int(request.form['age']),
            'sex': request.form['sex'],
            'bmi': float(request.form['bmi']),
            'children': int(request.form['children']),
            'smoker': request.form['smoker'],
            'region': request.form['region']
        }

        # 🔹 Convert form data to model-friendly format
        model_data = {
            'age': form_data['age'],
            'sex': 1 if form_data['sex'] == 'male' else 0,
            'bmi': form_data['bmi'],
            'children': form_data['children'],
            'smoker': 1 if form_data['smoker'] == 'yes' else 0,
            'region': {'northwest': 0, 'northeast': 1, 'southeast': 2, 'southwest': 3}[form_data['region']]
        }

        # 🔹 Predict current year cost
        df = pd.DataFrame([model_data])
        current_cost = model.predict(df)[0]
        form_data['cost'] = f"{current_cost:,.2f}"

        # 🔹 Explanation & Health Tips
        try:
            explanations = explain_prediction(model, model_data)
        except Exception as e:
            explanations = [f"AI खर्च का विश्लेषण नहीं कर सका (AI could not analyze the expense): {e}"]

        form_data['explanations'] = explanations
        form_data['health_tips'] = generate_health_tips(form_data)


        # 🔹 Future prediction check
        future_predictions = []
        if request.form.get("future_prediction") == "yes":
            base_age = model_data['age']
            base_bmi = model_data['bmi']
            current_smoker = model_data['smoker']
            for i in range(1, 6):
                future_model_data = model_data.copy()
                future_model_data['age'] = base_age + i
                future_model_data['bmi'] = base_bmi + (0.5 * i)  # Slight BMI increase yearly

                df_future = pd.DataFrame([future_model_data])
                future_cost = model.predict(df_future)[0]
                future_predictions.append({
                    'year': 2025 + i,
                    'cost': f"{future_cost:,.2f}"
                })

        form_data['future_predictions'] = future_predictions

        # 🔹 Return final report page
        return render_template('report.html', **form_data)

    except Exception as e:
        return render_template('index.html', prediction_text=f'Error: {str(e)}')





# How AI interpreted this expense
def explain_prediction(model, input_data):
    try:
        input_df = pd.DataFrame([input_data])

        # Use TreeExplainer for tree-based models
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(input_df)

        feature_labels = {
            'age': 'उम्र का असर (Effect of Age)',
            'sex': 'लिंग का असर (Effect of Gender)',
            'bmi': 'BMI का असर (Effect of BMI)',
            'children': 'बच्चों की संख्या का असर (Effect of Number of Children)',
            'smoker': 'धूम्रपान स्थिति का असर (Effect of Smoking Status)',
            'region': 'क्षेत्र का असर (Effect of Region)'
        }

        explanations = []
        for i, feature in enumerate(input_df.columns):
            label = feature_labels.get(feature, feature)
            value = shap_values[0][i]
            explanations.append(f"{label}: {round(value, 2)} रुपये (INR)")

        return explanations

    except Exception as e:
        return [f"AI खर्च का विश्लेषण नहीं कर सका (AI could not analyze the expense): {e}"]







@app.route('/generate_pdf', methods=['POST'])
def generate_pdf():
    try:
        html = render_template('report.html', **request.form)   
        pdf = io.BytesIO()
        pisa_status = pisa.CreatePDF(html, dest=pdf)

        if pisa_status.err:
            return "PDF Generation Error", 500

        pdf.seek(0)
        return send_file(pdf, download_name='medical_report.pdf', as_attachment=True)

    except Exception as e:
        return f"PDF Generation Failed: {str(e)}", 500






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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)