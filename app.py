from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import joblib
import sqlite3
import datetime
import traceback
import os

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "local-secret-key"
)

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('scans.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS job_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            job_text TEXT,
            risk_score REAL,
            is_fake BOOLEAN,
            scanned_by TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- LOAD AI MODEL ---
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    model = joblib.load(
        os.path.join(BASE_DIR, "scam_model.pkl")
    )

    vectorizer = joblib.load(
        os.path.join(BASE_DIR, "text_vectorizer.pkl")
    )
    print("AI Engine Online and Guarded.")
except Exception as e:
    print(f"Model error: {e}")

# ==========================================
# AUTHENTICATION ENGINE
# ==========================================
@app.route('/login')
def login_page():
    if session.get('logged_in'):
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    if session.get('logged_in'):
        return redirect(url_for('home'))
    return render_template('signup.html')

@app.route('/api/signup', methods=['POST'])
def do_signup():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not username or not password:
        return jsonify({'error': 'Fields cannot be blank.'}), 400
        
    try:
        conn = sqlite3.connect('scans.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, 'user'))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username is already registered.'}), 400

@app.route('/api/login', methods=['POST'])
def do_login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    conn = sqlite3.connect('scans.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        session['logged_in'] = True
        session['username'] = user['username']
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Invalid credentials.'}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ==========================================
# SECURE MODEL INFERENCE INTERFACE
# ==========================================
@app.route('/')
def home():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))
    return render_template('index.html', username=session.get('username'))

@app.route('/api/predict', methods=['POST'])
def predict_job():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 403
        
    data = request.json
    job_text = data.get('text', '')
    
    if not job_text.strip():
        return jsonify({'error': 'Input buffer empty. Supply a valid payload.'}), 400
        
    try:
        text_vectorized = vectorizer.transform([job_text])
        
        if text_vectorized.nnz == 0:
            return jsonify({
                'error': 'INVALID_PAYLOAD: No recognized vocabulary tokens detected. Process terminated.'
            }), 422
        
        prediction = model.predict(text_vectorized)
        probabilities = model.predict_proba(text_vectorized)[0]
        
        is_fake_native = bool(prediction[0].item() == 1)
        risk_score_native = float(round(probabilities[1].item() * 100, 2))
        
        feature_names = vectorizer.get_feature_names_out()
        coefficients = model.coef_[0]
        word_scores = [(feature_names[col], coefficients[col]) for col in text_vectorized.nonzero()[1]]
        word_scores.sort(key=lambda x: x[1], reverse=True)
        suspicious_words_native = [str(word) for word, score in word_scores[:3] if score > 0]
        
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        short_text = job_text[:100] + "..." if len(job_text) > 100 else job_text
        
        conn = sqlite3.connect('scans.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO job_scans (timestamp, job_text, risk_score, is_fake, scanned_by)
            VALUES (?, ?, ?, ?, ?)
        ''', (current_time, short_text, risk_score_native, is_fake_native, session.get('username')))
        conn.commit()
        conn.close()
        
        return jsonify({
            'is_fake': is_fake_native,
            'risk_score': risk_score_native,
            'suspicious_words': suspicious_words_native,
            'message': 'Analysis complete'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        current_user = session.get('username')
        conn = sqlite3.connect('scans.db')
        conn.row_factory = sqlite3.Row 
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM job_scans WHERE scanned_by = ? ORDER BY id DESC LIMIT 10', (current_user,))
        rows = cursor.fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        current_user = session.get('username')
        conn = sqlite3.connect('scans.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                COUNT(*), 
                SUM(CASE WHEN is_fake = 1 THEN 1 ELSE 0 END), 
                SUM(CASE WHEN is_fake = 0 THEN 1 ELSE 0 END) 
            FROM job_scans 
            WHERE scanned_by = ?
        ''', (current_user,))
        row = cursor.fetchone()
        conn.close()
        
        total_scans = row[0] if row[0] is not None else 0
        threats = row[1] if row[1] is not None else 0
        safe = row[2] if row[2] is not None else 0
        
        return jsonify({
            'total_scans': total_scans,
            'threats': threats,
            'safe': safe
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==========================================
# DATA ERASE SECURITY GATEWAY
# ==========================================
@app.route('/api/delete_scan/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        current_user = session.get('username')
        conn = sqlite3.connect('scans.db')
        cursor = conn.cursor()
        
        # Security Verification: Must match both scan ID and active session owner name
        cursor.execute('DELETE FROM job_scans WHERE id = ? AND scanned_by = ?', (scan_id, current_user))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)