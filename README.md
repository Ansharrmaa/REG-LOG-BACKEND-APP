# Registration & Login Service — Backend

A complete Spring Boot authentication backend for an e-commerce application. Provides user registration, login via email or mobile number, JWT-based session management, password recovery via email OTP, and password change.

---

## Table of Contents

- [Technology Stack](#technology-stack)
- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Local Setup](#local-setup)
- [Environment Variables](#environment-variables)
- [Database Setup](#database-setup)
- [Running the Application](#running-the-application)
- [Running Tests](#running-tests)
- [API Documentation](#api-documentation)
- [API Endpoints](#api-endpoints)
- [Security Design](#security-design)
- [Cookie & CSRF Configuration](#cookie--csrf-configuration)
- [SMTP / Email Setup](#smtp--email-setup)
- [Frontend Integration](#frontend-integration)
- [Known Limitations](#known-limitations)

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Java 21 (runs on JDK 21–24) |
| Framework | Spring Boot 3.4.1 |
| Security | Spring Security 6.x |
| Persistence | Spring Data JPA + Hibernate |
| Database | MySQL 8.0+ |
| Migrations | Flyway 10.x |
| JWT | JJWT 0.12.6 (HS256) |
| Password Hashing | BCrypt (strength 12) |
| Rate Limiting | Bucket4j 8.x + Caffeine (in-memory) |
| Email | Spring Mail / Jakarta Mail |
| Validation | Hibernate Validator / Bean Validation |
| API Docs | Springdoc OpenAPI 2.x |
| Testing | JUnit 5, Mockito, Spring Boot Test |
| Build | Maven + Maven Wrapper |

---

## Architecture Overview

```
src/main/java/com/auth/reglog/
├── config/          # SecurityConfig, JwtConfig, RateLimitConfig, OpenApiConfig
├── controller/      # HTTP handlers — AuthController
├── dto/
│   ├── request/     # RegisterRequest, LoginRequest, etc.
│   └── response/    # UserResponse, ApiResponse, ErrorResponse, VerifyOtpResponse
├── entity/          # User, AuthSession, PasswordRecoveryChallenge
├── repository/      # Spring Data JPA repositories
├── service/         # AuthService (business logic), EmailService, RateLimitService
├── security/        # JwtTokenProvider, JwtAuthenticationFilter, UserPrincipal
├── exception/       # GlobalExceptionHandler, custom exception types
├── validation/      # @PasswordMatch annotation + validator
└── util/            # CookieUtil, OtpUtil
```

**Design decisions:**
- Controllers handle HTTP only; business logic lives in services
- JPA entities are never returned directly as API responses
- Constructor injection throughout (via `@RequiredArgsConstructor`)
- All secrets come from environment variables; the app fails fast at startup if JWT_SECRET is absent or weak

---

## Prerequisites

| Requirement | Notes |
|---|---|
| JDK 21 or 24 | JDK 24 is installed on this machine. JDK 21 LTS also works. |
| MySQL 8.0+ | See [Database Setup](#database-setup) |
| Maven | NOT required — the Maven Wrapper (`mvnw.cmd`) is bundled |
| SMTP provider | Required only for OTP email delivery; mocked in tests |

---

## Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/Ansharrmaa/REG-LOG-BACKEND-APP.git
cd REG-LOG-BACKEND-APP
```

### 2. Set up environment variables

```bash
# Windows PowerShell — copy the example and fill in real values
Copy-Item .env.example .env
notepad .env
```

> ⚠️ `.env` is in `.gitignore`. **Never commit it.**

**Critical values you must fill in:**

```
SPRING_DATASOURCE_URL=jdbc:mysql://localhost:3306/reglog_db?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true
SPRING_DATASOURCE_USERNAME=root
SPRING_DATASOURCE_PASSWORD=your_mysql_password

# Generate with: openssl rand -base64 32 (or PowerShell: [Convert]::ToBase64String((1..32 | % { [byte](Get-Random -Max 256) })))
JWT_SECRET=your_base64_encoded_256bit_secret

COOKIE_SECURE=false   # false for local HTTP, true for production HTTPS
FRONTEND_ORIGIN=http://localhost:5173
```

### 3. Load environment variables before running

> ⚠️ **Java does not automatically load `.env` files.** You must set environment variables in your shell or IDE.

**PowerShell (recommended for local dev):**

```powershell
# Load .env into the current shell session
Get-Content .env | Where-Object { $_ -match '^[^#]' } | ForEach-Object {
    $parts = $_ -split '=', 2
    [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), 'Process')
}
```

**IntelliJ IDEA:**
- Run > Edit Configurations > Environment Variables → paste all key=value pairs

---

## Database Setup

### Option A: Manual MySQL 8 Installation (primary path — no Docker)

1. Download and install MySQL 8 from https://dev.mysql.com/downloads/installer/
2. During setup, note your root password
3. Create the database and user:

```sql
CREATE DATABASE reglog_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'reglog_user'@'localhost' IDENTIFIED BY 'your_strong_password';
GRANT ALL PRIVILEGES ON reglog_db.* TO 'reglog_user'@'localhost';
FLUSH PRIVILEGES;
```

### Option B: Docker Compose (if Docker is available)

```bash
docker compose up -d mysql
```

The schema is **never** created by Hibernate `ddl-auto`. Flyway migrations create all tables on startup:

- `V1__create_users_table.sql` — users table with unique email + mobile indexes
- `V2__create_auth_sessions_table.sql` — JWT session revocation table
- `V3__create_password_recovery_challenges_table.sql` — OTP + reset token storage

---

## Running the Application

### PowerShell (load env first, then run)

```powershell
# 1. Load environment variables from .env
Get-Content .env | Where-Object { $_ -match '^[^#]' } | ForEach-Object {
    $parts = $_ -split '=', 2
    [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), 'Process')
}

# 2. Run the application
.\mvnw.cmd spring-boot:run
```

The server starts at: **http://localhost:8080**

---

## Running Tests

Tests use **H2 in-memory database** and **mocked email service**. No MySQL or SMTP credentials are needed.

```powershell
.\mvnw.cmd test
```

To run only unit tests (no Spring context needed):

```powershell
.\mvnw.cmd test -Dtest="JwtTokenProviderTest,AuthServiceTest"
```

---

## API Documentation

Swagger UI: **http://localhost:8080/swagger-ui.html**  
OpenAPI JSON: **http://localhost:8080/api-docs**

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/auth/csrf` | None | Initialize CSRF token |
| `POST` | `/api/v1/auth/register` | None | Register new user |
| `POST` | `/api/v1/auth/login` | None | Login (email or mobile) |
| `POST` | `/api/v1/auth/logout` | Required | Revoke session, clear cookie |
| `GET` | `/api/v1/auth/me` | Required | Get current user |
| `POST` | `/api/v1/auth/forgot-password` | None | Send OTP to email |
| `POST` | `/api/v1/auth/verify-reset-otp` | None | Verify OTP, get reset token |
| `POST` | `/api/v1/auth/reset-password` | None | Reset password with token |
| `POST` | `/api/v1/auth/change-password` | Required | Change password (authenticated) |

### Example: Register

```http
POST /api/v1/auth/register
Content-Type: application/json
X-XSRF-TOKEN: <csrf-token>

{
  "fullName": "Example User",
  "email": "user@example.com",
  "mobileNumber": "9876543210",
  "password": "Example@123",
  "confirmPassword": "Example@123"
}
```

**Response 201:**
```json
{
  "id": 1,
  "fullName": "Example User",
  "email": "user@example.com",
  "mobileNumber": "9876543210"
}
```

### Example: Login

```http
POST /api/v1/auth/login
Content-Type: application/json
X-XSRF-TOKEN: <csrf-token>

{
  "identifier": "user@example.com",
  "password": "Example@123"
}
```

**Response 200:** Sets `AUTH_TOKEN` HttpOnly cookie. Body contains user info.

### Example Error Response

```json
{
  "timestamp": "2026-10-20T09:15:43Z",
  "status": 400,
  "error": "Bad Request",
  "message": "Validation failed",
  "path": "/api/v1/auth/register",
  "fieldErrors": {
    "email": "Invalid email address"
  }
}
```

---

## Security Design

### JWT

- Algorithm: **HS256**
- Secret: from `JWT_SECRET` environment variable (Base64-encoded, ≥32 bytes)
- Claims: `sub` (userId), `jti` (UUID), `iat`, `exp`, `iss`
- Default expiry: **30 minutes** (configurable via `JWT_EXPIRATION_MS`)
- Server-side revocation: every JWT maps to an `auth_sessions` row; logout and password reset mark it revoked

### Password Hashing

BCrypt with strength 12. No plaintext passwords are ever stored or logged.

### OTP Storage

OTPs are hashed with BCrypt before storage. The raw 6-digit OTP is never persisted or logged in production.

### Reset Token Storage

Reset tokens are opaque 32-byte random values, Base64URL-encoded. Only the SHA-256 hex hash is stored.

---

## Cookie & CSRF Configuration

### AUTH_TOKEN Cookie

| Attribute | Value |
|---|---|
| Name | `AUTH_TOKEN` (configurable via `AUTH_COOKIE_NAME`) |
| HttpOnly | ✅ Always enabled |
| Secure | `false` for local HTTP dev; `true` for production HTTPS |
| SameSite | `Lax` |
| Path | `/` |
| Max-Age | Same as JWT expiry (default: 1800 seconds) |

### CSRF Protection

- Spring Security `CookieCsrfTokenRepository` (XSRF-TOKEN cookie, X-XSRF-TOKEN request header)
- **Step 1:** Call `GET /api/v1/auth/csrf` to initialize the CSRF token
- **Step 2:** Read the `token` from the response JSON (or from the `XSRF-TOKEN` cookie)
- **Step 3:** Send `X-XSRF-TOKEN: <token>` header on all mutating requests (POST, PUT, DELETE)

---

## SMTP / Email Setup

The OTP email feature requires a real SMTP provider. **Gmail App Passwords** are the easiest option for development.

### Gmail App Password Setup

1. Enable 2FA on your Google account
2. Go to https://myaccount.google.com/apppasswords
3. Generate an app password for "Mail"
4. Set `MAIL_USERNAME=your-gmail@gmail.com` and `MAIL_PASSWORD=<16-char-app-password>`

> ⚠️ Regular Gmail passwords do NOT work for SMTP. You must use an App Password.

### Production SMTP

For production, use a dedicated email provider:
- **SendGrid:** `MAIL_HOST=smtp.sendgrid.net`, `MAIL_PORT=587`, `MAIL_USERNAME=apikey`, `MAIL_PASSWORD=<api-key>`
- **Mailgun:** `MAIL_HOST=smtp.mailgun.org`, `MAIL_PORT=587`
- **AWS SES:** `MAIL_HOST=email-smtp.<region>.amazonaws.com`, `MAIL_PORT=587`

---

## Frontend Integration

The frontend React app (`http://localhost:5173`) connects to this backend at `http://localhost:8080`.

**Required frontend steps:**
1. Call `GET /api/v1/auth/csrf` on app load to initialize the CSRF cookie
2. Extract the `X-XSRF-TOKEN` value from the response or from the `XSRF-TOKEN` cookie
3. Include `X-XSRF-TOKEN` header on all mutating requests
4. Use `credentials: 'include'` (fetch) or `withCredentials: true` (axios) on all requests so the AUTH_TOKEN cookie is sent automatically

**Frontend env:**
```
VITE_API_BASE_URL=http://localhost:8080/api/v1
```

---

## Known Limitations

1. **In-memory rate limiting**: Rate limits (login attempts, OTP requests) are stored in JVM memory per instance. In a multi-instance deployment, each instance has independent counters. To fix: replace with Redis-backed Bucket4j (`bucket4j-redis`).

2. **No refresh token**: JWT access tokens expire in 30 minutes. The frontend must redirect to login on 401. A refresh token system was intentionally omitted per scope requirements.

3. **Single change-password session policy**: All sessions (including the current one) are revoked when changing the password. The user must re-login. This is the secure default.

4. **Docker not available locally**: The `docker-compose.yml` is provided for environments with Docker. Manual MySQL installation is the primary local setup path.
