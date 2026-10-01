# TrustHire AI

**TrustHire AI** is a Flask-based web application that uses Natural Language Processing (NLP) and Machine Learning to analyze job advertisements and estimate whether a job posting may be fraudulent.

The application includes secure user authentication, scan history, statistics, suspicious-word indicators, PostgreSQL storage, and a responsive dashboard.

## Live Demo

**Live Website:** https://trusthair-ai.vercel.app

**GitHub Repository:** https://github.com/mhdihshas/TrustHair-AI

## Features

- AI-powered fake job detection
- Fraud risk percentage
- Suspicious keyword indicators
- User registration and login
- Secure password hashing
- Personal scan history
- User-specific statistics
- Delete scan history records
- PostgreSQL database integration
- Responsive desktop and mobile interface
- Dark/light interface support
- Deployed on Vercel

## Tech Stack

### Backend
- Python
- Flask
- Psycopg
- PostgreSQL
- Werkzeug Security

### Machine Learning
- Scikit-learn
- Logistic Regression
- TF-IDF Vectorization
- Joblib

### Frontend
- HTML5
- CSS3
- JavaScript
- Font Awesome
- Google Fonts

### Deployment & Database
- Vercel
- Neon PostgreSQL
- GitHub

## Project Structure

```text
TrustHair-AI/
│
├── app.py
├── requirements.txt
├── .python-version
├── .gitignore
│
├── scam_model.pkl
├── text_vectorizer.pkl
│
├── templates/
│   ├── index.html
│   ├── login.html
│   └── signup.html
│
├── clean_data.py
├── explore.py
└── train_model.py
```

## How It Works

1. A user creates an account and signs in.
2. The user pastes a job advertisement into the fraud analyzer.
3. The text is transformed using a trained TF-IDF vectorizer.
4. A trained Logistic Regression model analyzes the transformed text.
5. The application returns:
   - Fake/safe classification
   - Fraud risk score
   - Suspicious words detected by the model
6. The scan result is stored in PostgreSQL for the logged-in user.
7. The user can view statistics, history, and delete previous scans.

## Local Installation

### 1. Clone the Repository

```bash
git clone https://github.com/mhdihshas/TrustHair-AI.git
cd TrustHair-AI
```

### 2. Create a Virtual Environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

## Environment Variables

Create a file named:

```text
.env.local
```

Add:

```env
DATABASE_URL="your_postgresql_connection_string"
SECRET_KEY="your_random_secret_key"
```

To generate a Flask secret key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

> Never commit `.env.local`, database credentials, passwords, or secret keys to GitHub.

## Run Locally

After activating the virtual environment:

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Database

The application uses PostgreSQL.

When the application receives its first request, it creates the required tables if they do not already exist:

- `users`
- `job_scans`

User passwords are stored as password hashes rather than plain text.

## Main API Routes

| Route | Method | Purpose |
|---|---|---|
| `/api/signup` | POST | Create a user account |
| `/api/login` | POST | Log in |
| `/logout` | GET | Log out |
| `/api/predict` | POST | Analyze a job advertisement |
| `/api/history` | GET | Get recent scan history |
| `/api/stats` | GET | Get user statistics |
| `/api/delete_scan/<id>` | DELETE | Delete a scan record |

## Deployment

The project is deployed on **Vercel**.

Production environment variables should be configured in the Vercel project settings:

```text
DATABASE_URL
SECRET_KEY
```

The PostgreSQL database can be hosted using Neon.

After pushing changes to the `main` branch, Vercel can automatically redeploy the project.

## Security

The project includes:

- Password hashing using Werkzeug
- Session-based authentication
- User-specific scan history
- Database credentials stored as environment variables
- Protected API routes for authenticated users

## Important Note

TrustHire AI is an educational and portfolio project. Machine-learning predictions should be treated as an additional indicator rather than definitive proof that a job advertisement is genuine or fraudulent.

## Author

**Mohamed Ihshas**

HNDIT Student / IT Developer

GitHub: https://github.com/mhdihshas

## License

This project is currently provided for educational and portfolio purposes.
