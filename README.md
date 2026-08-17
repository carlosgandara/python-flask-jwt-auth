
🔐 Python Flask JWT Authentication with Refresh Token Rotation

Enterprise-grade, production-ready authentication system built with Flask. Features HttpOnly cookies, refresh token rotation, silent frontend recovery, and Neon PostgreSQL.

✨ Features

🔐 Register with email + password (bcrypt hashed)

📧 Email verification (expires in 24h)

🍪 HttpOnly Cookies – Tokens are invisible to JavaScript (XSS-safe)

🔑 JWT Access Token (short-lived, stored in HttpOnly cookie)

🔄 Refresh Token Rotation – Long-lived, hashed in DB, invalidated on use (replay attack proof)

🛡️ Silent Token Refresh – Frontend catches 401s, calls /refresh automatically, and retries requests

📊 Protected Pages – /dashboard and /profile with cookie-based auth

🚪 Secure Logout – Revokes refresh token in DB and deletes cookies

📨 Password Reset (expires in 15min)

🖥️ Web UI – AJAX forms with automatic redirects

🐘 PostgreSQL Database – Managed via Neon (serverless, scalable, auto-backup)

⏱️ Rate Limiting – Per-IP and per-IP+User combo protection

🛠️ Tech Stack

Backend: 🐍 Flask (Python 3.10+)

Auth: 🔐 PyJWT + bcrypt

Cookies: 🍪 HttpOnly, Secure, SameSite=Lax

Database: 🐘 PostgreSQL via Neon (serverless) with SQLAlchemy ORM

Email: ✉️ SMTP (Brevo / Sendinblue / Gmail)

Frontend: 🌐 HTML + vanilla JS (no frameworks required)

📁 Project Structure

python-flask-jwt-auth/
├── 🚀 app.py # Main Flask app with refresh endpoints
├── ⚙️ config.py # Configuration + environment variables
├── 🔒 .env # SMTP + JWT + DATABASE_URL secrets (ignored by Git)
├── 📄 .gitignore # Ignores .env, pycache, etc.
├── 📦 requirements.txt # Python dependencies
├── 📂 utils/
│ ├── 🗃️ db.py # SQLAlchemy + PostgreSQL (Neon)
│ └── ✉️ mail_service.py # SMTP email sender
└── 📂 templates/
├── 🏗️ base.html # Base layout
├── 🔑 login.html # Login form (redirects to dashboard)
├── 📝 register.html # Registration form
├── 🔄 forgot_password.html # Request reset link
├── 🔐 reset_password.html # Reset password form
├── 📊 dashboard.html # Protected dashboard (with silent refresh)
├── 👤 profile.html # Protected profile page
├── ✅ verify_success.html # Email verified
└── ❌ verify_error.html # Verification failed

🚀 Setup

Clone the repository:
git clone https://github.com/carlosgandara/python-flask-jwt-auth.git
cd python-flask-jwt-auth

Create and activate a virtual environment:
python -m venv venv
source venv/bin/activate # Mac/Linux
venv\Scripts\activate # Windows

Install dependencies:
pip install -r requirements.txt

Create a .env file (see example below):
EMAIL_HOST=smtp-relay.brevo.com
EMAIL_PORT=587
EMAIL_USER=your-smtp-username
EMAIL_PASS=your-smtp-password
EMAIL_FROM=your-email@example.com
JWT_SECRET_KEY=your-very-long-secret-min-32-chars
DATABASE_URL=postgresql://user:password@host/database

Run the app:
python app.py

Open your browser:
Visit http://localhost:5000/login

Note: .env is ignored by Git – your secrets stay safe.

🌐 API Endpoints

POST /register – Create user + send verification email (No auth required)
GET /verify-email – Verify email with token (No auth required)
POST /login – Set access_token and refresh_token as HttpOnly cookies (No auth required)
POST /refresh – Rotate tokens (issue new Access + Refresh) (Refresh Cookie required)
GET /protected – Test route – returns user email (Access Cookie required)
GET /dashboard – Protected HTML page (Access Cookie required)
GET /profile – Protected HTML page (Access Cookie required)
POST /logout – Revoke refresh token + delete cookies (Access Cookie required)
POST /forgot-password – Request password reset link (No auth required)
POST /reset-password – Reset password with token (No auth required)

🧪 Testing with curl (Windows CMD)

Important: The new flow uses HttpOnly cookies. Use -c to save cookies and -b to send them.

Login (saves cookies to cookies.txt):
curl -X POST http://localhost:5000/login -H "Content-Type: application/json" -d "{"email":"test@example.com","password":"123456"}" -c cookies.txt -i

Access protected endpoint (uses saved cookie):
curl -X GET http://localhost:5000/protected -b cookies.txt

Refresh tokens (rotation – kills old token):
curl -X POST http://localhost:5000/refresh -b cookies.txt -c cookies_new.txt -i

Prove rotation works (reuse old token – fails):
curl -X POST http://localhost:5000/refresh -b cookies.txt
Expected: {"error": "Invalid or expired refresh token"} (replay attack blocked)

Logout (revokes token + deletes cookies):
curl -X POST http://localhost:5000/logout -b cookies.txt -c cookies.txt -i

👨‍💻 Web UI Walkthrough

📝 Register – Fill in email/password → receive verification email.
✅ Verify – Click the link in your email.
🔑 Login – Enter credentials → automatically redirected to /dashboard.
📊 Dashboard – Shows your protected user data. Click "Refresh Data" to test the API.
👤 Profile – Another protected page (demonstrates cookie persistence).
🔄 Silent Refresh – If you wait for the Access Token to expire (e.g., 1 min) and click "Refresh Data", the frontend silently calls /refresh and retries – you never see a login screen.
🚪 Logout – Clears cookies and revokes the refresh token in the database.

✉️ Email Configuration

Works with any SMTP provider:

Brevo (Sendinblue) – Recommended (free tier)

Gmail – Use an App Password

SendGrid, Mailgun, etc.

🐘 Neon PostgreSQL Setup

Sign up for Neon at https://neon.tech

Create a new project

Copy your connection string:
DATABASE_URL=postgresql://user:password@host/database

Add it to your .env file

🛡️ Security Highlights

Password storage: bcrypt (12 rounds)
JWT signing: HMAC-SHA256 with secret key
Refresh tokens: Hashed in database (bcrypt), revoked on rotation
Cookies: HttpOnly (XSS-safe), Secure (HTTPS-only), SameSite=Lax (CSRF protection)
Verification tokens: Plain storage (can be upgraded to hashed)
Rate limiting: Per-IP and per-IP+User combo (in-memory for development)

🚀 Future Improvements

Add Redis for rate limiting (production ready)

Add Redis for rate limiting (production ready)

Change password endpoint

Hashed verification tokens

Unit tests

Admin panel

📄 License

MIT License

Copyright (c) 2024 Carlos Gandara

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

👤 Author

Carlos Gandara
🔗 GitHub: https://github.com/carlosgandara

⭐ If you found this useful, please give it a star!
