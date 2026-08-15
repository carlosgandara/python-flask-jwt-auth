# Python Flask JWT Authentication with Rate Limiting & Account Security

A production-ready authentication system built with **Flask**, **JWT**, and **email verification**. This project implements **three layers of brute-force protection** to stop both distributed and single-source password attacks.

## Features
- 🔐 **User Registration** with email verification (24h expiry)
- 🔑 **JWT Authentication** (stateless, 1h expiry)
- 📧 **Password Reset** flow with secure tokens (15min expiry)
- 🖥️ **Web UI** with AJAX forms (no page reloads)
- 📁 **JSON Database** (ready to swap for PostgreSQL/SQLite)

## 🛡️ Security Highlights (3 Layers of Protection)

This system uses a **defense-in-depth** approach to stop brute-force attacks:

| Layer | Protection | Limit | Purpose |
| :--- | :--- | :--- | :--- |
| **Layer 1** | **Global IP Rate Limit** | `5 requests per minute` | Stops general flooding from a single IP (using Flask-Limiter). |
| **Layer 2** | **IP + User Combo Limit** | `5 attempts per 5 minutes` | Stops an attacker from trying thousands of passwords on a specific user from one IP. *(Tracked in server memory)* |
| **Layer 3** | **Per-User Account Lockout** | `5 failed attempts → 15 min lock` | Stops distributed attacks (botnets) where attackers use many different IPs to attack the *same* user account. |

> **Why Layer 2 & 3 are separate?**  
> *Layer 2* blocks the *IP* for 5 minutes (so they can't try 1000 more times instantly).  
> *Layer 3* blocks the *Account* for 15 minutes (so even if they switch to 100 different IPs, they can't bypass the lockout).

## Tech Stack
- **Backend**: Flask (Python)
- **Auth**: PyJWT + bcrypt
- **Rate Limits**: Flask-Limiter + Custom In-Memory Tracker
- **Email**: SMTP (Brevo / Sendinblue)
- **DB**: JSON file (local)

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/carlosgandara/python-flask-jwt-auth.git
cd python-flask-jwt-auth
```

### 2. Create Virtual Environment & Install Dependencies
```bash
python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Create a `.env` file in the root directory:
```env
EMAIL_HOST=smtp-relay.brevo.com
EMAIL_PORT=587
EMAIL_USER=your-smtp-username
EMAIL_PASS=your-smtp-password
EMAIL_FROM=your-email@example.com
JWT_SECRET_KEY=your-very-long-secret-min-32-chars
```

### 4. Run the Application
```bash
python app.py
```
The server will start at `http://localhost:5000`.

## API Endpoints
| Method | Endpoint | Description | Rate Limited? |
| :--- | :--- | :--- | :--- |
| POST | `/register` | Create user + send verification | ✅ 5/min |
| GET | `/verify-email` | Verify email with token | ❌ |
| POST | `/login` | Authenticate and get JWT | ✅ 5/min + Combo |
| GET | `/protected` | Access protected route (requires JWT) | ❌ |
| POST | `/forgot-password` | Request a reset link | ✅ 5/min |
| POST | `/reset-password` | Reset password with token | ✅ 5/min |

## 🧪 Testing the Rate Limits with `curl` (Windows CMD)

### 1. Test the IP+User Combo Limit
This test simulates a single attacker trying to brute-force one specific user from a single IP.

*Send 6 failed login attempts in quick succession:*
```cmd
curl -X POST http://localhost:5000/login -H "Content-Type: application/json" -d "{\"email\":\"test@example.com\",\"password\":\"wrong\"}"
```

**Expected Response Flow:**
- **Attempts 1–5:** `{"error": "Invalid credentials"}` (401)
- **Attempt 6:** `{"error": "Too many failed login attempts from this IP for this user. Please wait 5 minutes."}` (429)

### 2. Test the Global IP Rate Limit
This stops you from hammering the server with general requests.

*Send 6 requests rapidly (any endpoint):*
```cmd
curl -X POST http://localhost:5000/login -H "Content-Type: application/json" -d "{\"email\":\"test@example.com\",\"password\":\"wrong\"}"
```

**Expected Response:**
- **Attempt 6:** `{"error": "Too many requests. Please slow down."}` (429)

### 3. Test the Account Lockout
This protects against distributed attacks (where the attacker uses many different IPs).

*Send 5 failed attempts for the same user (wait 1 minute between them to avoid the Global IP limit, or raise the global limit temporarily).*
After the 5th failure, the account is locked.

**Expected Response on the 6th attempt:**
```json
{"error": "Account locked. Try again in 15 minute(s)."}
```

## Project Structure
```
python-flask-jwt-auth/
├── app.py                 # Core application & route definitions
├── config.py              # Environment variables & constants
├── utils/
│   ├── db.py              # JSON database helpers
│   └── mail_service.py    # Email sending logic
├── templates/             # Jinja2 HTML templates
├── user_db.json           # Auto-created database (ignored by Git)
└── .env                   # Sensitive variables (ignored by Git)
```

## Security Notes
- Passwords are hashed using `bcrypt` (12 rounds).
- JWT tokens are signed with a strong secret (min 32 chars).
- Reset tokens are hashed before storage.
- **Important**: `.env` and `user_db.json` are excluded via `.gitignore`.

## Future Improvements
- [ ] Replace JSON with SQLite/PostgreSQL (SQLAlchemy)
- [ ] Add Refresh Tokens for extended sessions
- [ ] Integrate Redis for persistent rate-limit storage across restarts
- [ ] Implement 2FA (TOTP)

## License
MIT License

Copyright (c) 2024 Carlos Gandara

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Author
Carlos Gandara – [GitHub](https://github.com/carlosgandara)
