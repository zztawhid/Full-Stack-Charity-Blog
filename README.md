# Animal Charity Blog

A secure web-based animal charity blog system built with Node.js, Express, and PostgreSQL. Designed to demonstrate comprehensive security mitigations including MFA, encrypted database fields, CSRF protection, rate limiting, and more.

## Prerequisites

- **Node.js** v18 or higher
- **PostgreSQL** v14 or higher (with pgcrypto extension)
- **Stripe CLI** (optional, for webhook testing)
- A Stripe account with test API keys
- An SMTP service for emails (e.g. Mailtrap for development)

## Project Structure

```
/project
  /public
    /css/style.css        — Stylesheet
    /js/main.js           — Minimal client-side JS
  /views                  — EJS templates
    /partials             — Header and footer
    /admin                — Admin panel views
  /routes                 — Express route handlers
  /middleware             — Security middleware
  /db
    schema.sql            — Database schema
    pool.js               — PostgreSQL connection pool
    seed.js               — Admin account seeder
  /uploads                — Uploaded pet images (auto-created)
  server.js               — Express application entry point
  .env                    — Environment variables (not committed)
  .env.example            — Template with all required variables
  package.json            — Dependencies
  README.md               — This file
```

## Setup Instructions

### 1. Clone and install dependencies

```bash
cd CW2-DSS
npm install
```

### 2. Create the PostgreSQL database

```bash
# Connect to PostgreSQL
psql -U postgres

# Create the database
CREATE DATABASE charity_blog;

# Connect to it
\c charity_blog

# Enable pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

# Exit psql
\q
```

### 3. Run the database schema

```bash
psql -U postgres -d charity_blog -f db/schema.sql
```

creates all required tables: `users`, `posts`, `comments`, `donations`, `newsletter_posts`, `audit_log`, `password_reset_tokens`, and `session`.

### 4. Create the .env file

Required variables:

`DB_HOST` - PostgreSQL host (usually `localhost`) 
`DB_PORT` - PostgreSQL port (usually `5432`) 
`DB_NAME` - Database name (`charity_blog`) 
`DB_USER` - PostgreSQL username 
`DB_PASSWORD` - PostgreSQL password 
`SESSION_SECRET` - Long random string for session signing 
`PEPPER` - Server-side pepper for password hashing 
`DB_ENCRYPTION_KEY` - Key for pgcrypto column encryption 
`STRIPE_SECRET_KEY` - Stripe test secret key (`sk_test_...`) 
`STRIPE_PUBLISHABLE_KEY` - Stripe test publishable key (`pk_test_...`) 
`STRIPE_WEBHOOK_SECRET` - Stripe webhook signing secret 
`EMAIL_HOST` - SMTP host 
`EMAIL_PORT` - SMTP port 
`EMAIL_USER` - SMTP username
`EMAIL_PASS` - SMTP password 
`EMAIL_FROM` - From address for emails 
`TOTP_APP_NAME` - Name shown in authenticator apps 
`ADMIN_USERNAME` - Initial admin username 
`ADMIN_EMAIL` - Initial admin email 
`ADMIN_PASSWORD` - Initial admin password

### 5. Seed the admin account

```bash
npm run seed
```

This creates the initial admin user and outputs the TOTP secret. **Add this secret to your authenticator app** (e.g. Google Authenticator) to enable MFA login for the admin account.

### 6. Start the server

```bash
npm start
```

The server starts at `http://localhost:3000` (or the port in your .env).

### 7. Stripe webhook (for donation confirmation)

In terminal

```bash
stripe listen --forward-to localhost:3000/donations/webhook
```

webhook signing secret (`whsec_...`) and set it as `STRIPE_WEBHOOK_SECRET`in env file

## Stripe testing

The application uses Stripe in test mode by default. Use these test card numbers:

- **Successful payment:** `4242 4242 4242 4242`
- **Requires authentication:** `4000 0025 0000 3155`
- **Declined:** `4000 0000 0000 0002`

Use any future expiry date, any 3-digit CVC, and any postcode.

## Features

### Pages
- **Home** — Landing page with recent blog posts
- **Blog** — Feed of all posts with create/edit/delete
- **Post detail** — Single post view with comments and donation pool
- **Newsletter** — Subscribe/unsubscribe, view published newsletters
- **Donations** — Stripe-powered one-off and monthly donations
- **Settings** — Change password, change email, delete account
- **Admin** — Dashboard, user management, post management, newsletter creation, audit log

### Security Mitigations
1. Account enumeration prevention
2. Session hijacking prevention (httpOnly, secure, sameSite, User-Agent binding)
3. SQL injection prevention (parameterised queries everywhere)
4. XSS prevention (server-side sanitisation + CSP headers)
5. CSRF protection (csurf tokens on every form)
6. Password hashing with bcrypt + server-side pepper
7. Database encryption (pgcrypto for email, TOTP secret, Stripe ID)
8. TOTP multi-factor authentication
9. Rate limiting on login
10. Account lockout after failed attempts
11. Helmet.js security headers
12. File upload security (MIME validation, UUID rename, size limit)
13. IDOR prevention on all edit/delete routes
14. Role-based access control
15. Audit logging of admin actions
16. Re-authentication on settings changes
17. Password strength enforcement
18. Input validation with express-validator

