from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import joblib
import numpy as np

app = Flask(__name__)
app.secret_key = 'secret-key'

model = joblib.load('diabetes_pipeline.pkl')

def init_db():
    with sqlite3.connect('users.db') as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )""")
init_db()

@app.route('/')
def home():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        with sqlite3.connect('users.db') as conn:
            try:
                conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
                return redirect(url_for('login'))
            except:
                return "User already exists!"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('users.db') as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cur.fetchone()
            if user and check_password_hash(user[2], password):
                session['user'] = username
                return redirect(url_for('home'))
            return "Invalid Credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/predict', methods=['POST'])
def predict():
    if 'user' not in session:
        return redirect(url_for('login'))
    try:
        data = [
            float(request.form['pregnancies']),
            float(request.form['glucose']),
            float(request.form['bloodpressure']), 0,
            float(request.form['insulin']),
            float(request.form['bmi']), 0.5,
            float(request.form['age'])
        ]
        input_array = np.array([data])
        prediction = model.predict(input_array)[0]
        confidence = max(model.predict_proba(input_array)[0]) * 100
        if prediction == 1:
            result = "⚠ High risk of Diabetes"
        else:
            result = "✅ No Diabetes detected"
        return render_template('index.html', prediction=result, confidence=round(confidence, 2))
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True)