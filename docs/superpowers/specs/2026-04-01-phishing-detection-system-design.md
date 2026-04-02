# Phishing Detection System - Complete Design Specification

## Project Overview
- **Project Name**: PhishGuard - Zero-Day Phishing Detection System
- **Type**: Full-stack Flask Web Application
- **Core Functionality**: Enterprise-grade phishing URL detection with ML ensemble, real-time monitoring, and comprehensive reporting
- **Target Users**: Security analysts, IT administrators, enterprise security teams

## Technical Stack
- **Backend**: Flask 2.3+ with Flask-RESTx, Flask-SocketIO
- **Database**: SQLite (development), PostgreSQL-ready
- **Caching**: Redis with Flask-Caching
- **Task Queue**: Celery with Redis broker
- **Frontend**: Bootstrap 5, Chart.js, PWA
- **ML**: Simulated heuristics (Random Forest, XGBoost, LSTM, BERT)
- **Docker**: Multi-stage Dockerfile, docker-compose.yml

## Feature Specifications

### 1. Authentication & Security
| Feature | Implementation |
|---------|---------------|
| Password Hashing | PBKDF2 with 100,000 iterations + salt |
| Session Management | Flask-Login with secure cookies |
| 2FA | TOTP using pyotp, QR code setup |
| Password Strength | zxcvbn library integration |
| Rate Limiting | Flask-Limiter (10 req/min), Redis-backed |
| Audit Logging | All security events logged to database |

### 2. Phishing Detection Engine (25+ Heuristics)
| Category | Heuristics |
|----------|------------|
| URL Analysis | Length, special chars, encoded chars, entropy, suspicious TLDs |
| Domain Analysis | Subdomain count, IP address detection, typosquatting |
| HTML Analysis | Login form detection, brand impersonation, hidden elements |
| SSL Analysis | Issuer, expiry, certificate transparency |
| DNS Analysis | SPF, DKIM, DMARC record validation |
| Redirect Analysis | Chain depth, final URL vs original |
| Content Analysis | Multi-language detection, urgency patterns |

### 3. ML Ensemble (Simulated)
- **Random Forest**: 100 decision trees simulating feature importance
- **XGBoost**: Gradient boosting simulation
- **LSTM**: Sequence pattern detection (URL structure)
- **BERT**: NLP-based content analysis simulation
- **Weighted Voting**: Configurable weights per model

### 4. REST API
- Flask-RESTx with OpenAPI/Swagger documentation
- API key generation and rotation
- Rate limiting per endpoint
- Endpoints: /analyze, /bulk, /watchlist, /reports, /users

### 5. Real-time Features
- WebSocket for bulk scan progress streaming
- Live dashboard with Chart.js visualizations
- APScheduler for 24-hour periodic re-analysis

### 6. Background Tasks (Celery)
- Bulk URL analysis with CSV upload
- Screenshot capture (Selenium headless)
- Periodic watchlist re-analysis
- PDF report generation

### 7. User Features
- Watchlist management with email notifications
- Analysis history with CSV/PDF export
- Feedback loop (false positive/negative reporting)
- Confidence score adjustment

### 8. Admin Dashboard
- User management (CRUD)
- System-wide analytics
- Model performance metrics
- Activity logging
- API usage analytics

### 9. PWA Features
- manifest.json for installation
- Service workers for offline caching
- Push notifications for critical alerts

## Database Schema

### Users Table
- id, username, email, password_hash, totp_secret, api_key, role, created_at, last_login

### Analysis Results Table
- id, user_id, url, result (safe/suspicious/phishing), confidence, heuristics_used, created_at

### Watchlist Table
- id, user_id, url, status, last_checked, notify_on_change

### Feedback Table
- id, user_id, analysis_id, feedback_type (fp/fn), resolved, created_at

### Audit Log Table
- id, user_id, event_type, details, ip_address, created_at

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/register | User registration |
| POST | /api/auth/login | User login |
| POST | /api/auth/2fa/setup | Initialize 2FA |
| POST | /api/auth/2fa/verify | Verify 2FA code |
| GET | /api/analyze/<url> | Single URL analysis |
| POST | /api/bulk/analyze | Bulk URL analysis (CSV) |
| GET | /api/bulk/<batch_id> | Get bulk results |
| GET | /api/watchlist | Get user watchlist |
| POST | /api/watchlist | Add URL to watchlist |
| DELETE | /api/watchlist/<id> | Remove from watchlist |
| POST | /api/feedback | Submit feedback |
| GET | /api/reports | Get analysis history |
| GET | /api/admin/users | Admin: list users |
| GET | /api/admin/analytics | Admin: system analytics |

## Acceptance Criteria
1. User can register, login, enable 2FA
2. Single URL analysis returns result in <3 seconds
3. Bulk analysis processes 1000 URLs with progress streaming
4. All 25+ heuristics produce meaningful scores
5. ML ensemble combines predictions with weighted voting
6. Watchlist re-analyzes every 24 hours automatically
7. PDF reports generate with executive summary
8. Docker deployment works with single command
9. API rate limiting enforces 10 req/min
10. PWA installs on mobile and works offline