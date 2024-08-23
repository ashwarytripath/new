from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pickle
import numpy as np
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/ashwa/Downloads/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Load model and scaler
model = pickle.load(open('rf_classifier.pkl', 'rb'))
scaler = pickle.load(open('scaler.pkl', 'rb'))

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    male = db.Column(db.Integer, nullable=False)
    age = db.Column(db.Integer, nullable=False)
    currentSmoker = db.Column(db.Integer, nullable=False)
    cigsPerDay = db.Column(db.Float, nullable=False)
    BPMeds = db.Column(db.Integer, nullable=False)
    prevalentStroke = db.Column(db.Integer, nullable=False)
    prevalentHyp = db.Column(db.Integer, nullable=False)
    diabetes = db.Column(db.Integer, nullable=False)
    totChol = db.Column(db.Float, nullable=False)
    sysBP = db.Column(db.Float, nullable=False)
    diaBP = db.Column(db.Float, nullable=False)
    BMI = db.Column(db.Float, nullable=False)
    heartRate = db.Column(db.Float, nullable=False)
    glucose = db.Column(db.Float, nullable=False)
    prediction = db.Column(db.String(80), nullable=False)

# Create database tables
with app.app_context():
    db.create_all()

# Prediction function
def predict(model, scaler, male, age, currentSmoker, cigsPerDay, BPMeds, prevalentStroke, prevalentHyp, diabetes,
            totChol, sysBP, diaBP, BMI, heartRate, glucose):
    features = np.array([[male, age, currentSmoker, cigsPerDay, BPMeds, prevalentStroke, prevalentHyp, diabetes,
                          totChol, sysBP, diaBP, BMI, heartRate, glucose]])
    scaled_features = scaler.transform(features)
    result = model.predict(scaled_features)
    return result[0]

# Routes
@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different username.', 'warning')
            return redirect(url_for('register'))

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('index'))

        flash('Login failed. Check your credentials and try again.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/predict', methods=['POST'])
def predict_route():
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        male = int(request.form['male'])
        age = int(request.form['age'])
        currentSmoker = int(request.form['currentSmoker'])
        cigsPerDay = float(request.form['cigsPerDay'])
        BPMeds = int(request.form['BPMeds'])
        prevalentStroke = int(request.form['prevalentStroke'])
        prevalentHyp = int(request.form['prevalentHyp'])
        diabetes = int(request.form['diabetes'])
        totChol = float(request.form['totChol'])
        sysBP = float(request.form['sysBP'])
        diaBP = float(request.form['diaBP'])
        BMI = float(request.form['BMI'])
        heartRate = float(request.form['heartRate'])
        glucose = float(request.form['glucose'])

        prediction = predict(model, scaler, male, age, currentSmoker, cigsPerDay, BPMeds, prevalentStroke, prevalentHyp,
                             diabetes, totChol, sysBP, diaBP, BMI, heartRate, glucose)
        prediction_text = "The Patient will have Heart Disease" if prediction == 1 else "The Patient will not have Heart Disease"

        user = User.query.filter_by(username=session['username']).first()
        new_report = Report(user_id=user.id, male=male, age=age, currentSmoker=currentSmoker, cigsPerDay=cigsPerDay,
                            BPMeds=BPMeds, prevalentStroke=prevalentStroke, prevalentHyp=prevalentHyp, diabetes=diabetes,
                            totChol=totChol, sysBP=sysBP, diaBP=diaBP, BMI=BMI, heartRate=heartRate, glucose=glucose,
                            prediction=prediction_text)
        db.session.add(new_report)
        db.session.commit()

        return render_template('index.html', prediction=prediction_text)

    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/reports')
def reports():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    reports = Report.query.filter_by(user_id=user.id).all()

    return render_template('reports.html', reports=reports)

if __name__ == '__main__':
    app.run(debug=True)

