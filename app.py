from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import joblib
import datetime
import traceback
import os
import psycopg

from psycopg.rows import dict_row
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "local-secret-key"
)

DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL or POSTGRES_URL is not configured")

# --- DATABASE SETUP ---
def get_db():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


def init_db():
    with get_db() as conn:
        with conn.cursor() as cursor:

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user'
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS job_scans (
                    id SERIAL PRIMARY KEY,
                    timestamp TEXT,
                    job_text TEXT,
                    risk_score REAL,
                    is_fake BOOLEAN,
                    scanned_by TEXT
                )
            """)

        conn.commit()

    _db_initialized = False

@app.before_request
def ensure_database():
    global _db_initialized

    if not _db_initialized:
        init_db()
        _db_initialized = True


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
    data = request.get_json(silent=True) or {}

    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({
            'error': 'Fields cannot be blank.'
        }), 400

    try:
        password_hash = generate_password_hash(password)

        with get_db() as conn:
            with conn.cursor() as cursor:

                cursor.execute("""
                    INSERT INTO users
                    (username, password_hash, role)
                    VALUES (%s, %s, %s)
                """, (
                    username,
                    password_hash,
                    'user'
                ))

            conn.commit()

        return jsonify({
            'success': True
        })

    except psycopg.errors.UniqueViolation:

        return jsonify({
            'error': 'Username is already registered.'
        }), 400

    except Exception as e:

        print("Signup error:", e)

        return jsonify({
            'error': 'Database error. Please try again.'
        }), 500

@app.route('/api/login', methods=['POST'])
def do_login():
    data = request.get_json(silent=True) or {}

    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    try:

        with get_db() as conn:
            with conn.cursor() as cursor:

                cursor.execute("""
                    SELECT *
                    FROM users
                    WHERE username = %s
                """, (username,))

                user = cursor.fetchone()

        if user and check_password_hash(
            user['password_hash'],
            password
        ):

            session['logged_in'] = True
            session['username'] = user['username']

            return jsonify({
                'success': True
            })

        return jsonify({
            'error': 'Invalid credentials.'
        }), 401

    except Exception as e:

        print("Login error:", e)

        return jsonify({
            'error': 'Database error.'
        }), 500

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
        
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO job_scans
                    (
                        timestamp,
                        job_text,
                        risk_score,
                        is_fake,
                        scanned_by
                    )
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    current_time,
                    short_text,
                    risk_score_native,
                    is_fake_native,
                    session.get('username')
                ))

            conn.commit()
        
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

        with get_db() as conn:
            with conn.cursor() as cursor:

                cursor.execute("""
                    SELECT *
                    FROM job_scans
                    WHERE scanned_by = %s
                    ORDER BY id DESC
                    LIMIT 10
                """, (current_user,))

                rows = cursor.fetchall()

        return jsonify(rows)

    except Exception as e:

        print("History error:", e)

        return jsonify({
            'error': 'Database error'
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():

    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 403

    try:

        current_user = session.get('username')

        with get_db() as conn:
            with conn.cursor() as cursor:

                cursor.execute("""
                    SELECT
                        COUNT(*) AS total,
                        COUNT(*) FILTER
                        (WHERE is_fake = TRUE) AS threats,
                        COUNT(*) FILTER
                        (WHERE is_fake = FALSE) AS safe
                    FROM job_scans
                    WHERE scanned_by = %s
                """, (current_user,))

                row = cursor.fetchone()

        return jsonify({
            'total_scans': row['total'] or 0,
            'threats': row['threats'] or 0,
            'safe': row['safe'] or 0
        })

    except Exception as e:

        print("Stats error:", e)

        return jsonify({
            'error': 'Database error'
        }), 500

# ==========================================
# DATA ERASE SECURITY GATEWAY
# ==========================================
@app.route('/api/delete_scan/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        current_user = session.get('username')

        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    DELETE FROM job_scans
                    WHERE id = %s
                    AND scanned_by = %s
                """, (
                    scan_id,
                    current_user
                ))

            conn.commit()

        return jsonify({'success': True})

    except Exception as e:
        print("Delete error:", e)

        return jsonify({
            'error': 'Database error'
        }), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)