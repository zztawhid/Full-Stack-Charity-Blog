-- ============================================================
-- Animal Charity Blog — Database Schema
-- ============================================================
-- This schema uses PostgreSQL with the pgcrypto extension for
-- column-level encryption of sensitive data (email, TOTP secret,
-- Stripe customer ID). All encrypted columns are stored as BYTEA.
-- ============================================================

-- Enable pgcrypto for pgp_sym_encrypt / pgp_sym_decrypt
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- Sessions table (managed by connect-pg-simple)
-- Stores express-session data server-side in PostgreSQL
-- ============================================================
CREATE TABLE "session" (
  "sid"    VARCHAR NOT NULL COLLATE "default",
  "sess"   JSON    NOT NULL,
  "expire" TIMESTAMP(6) NOT NULL
) WITH (OIDS=FALSE);

ALTER TABLE "session"
  ADD CONSTRAINT "session_pkey"
  PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;

CREATE INDEX "IDX_session_expire" ON "session" ("expire");

-- ============================================================
-- Users table
-- email, totp_secret, and stripe_customer_id are encrypted
-- email_hash stores a SHA-256 digest for email-based lookups
-- ============================================================
CREATE TABLE users (
  id                  SERIAL PRIMARY KEY,
  username            VARCHAR(50) UNIQUE NOT NULL,
  email               BYTEA NOT NULL,                -- pgp_sym_encrypt(plaintext_email, key)
  email_hash          VARCHAR(128) NOT NULL,          -- SHA-256 hex for lookups (forgot-password)
  password_hash       VARCHAR(255) NOT NULL,          -- bcrypt hash (pepper + password)
  pepper_version      INTEGER DEFAULT 1,
  totp_secret         BYTEA,                          -- pgp_sym_encrypt(base32_secret, key)
  totp_verified       BOOLEAN DEFAULT FALSE,          -- true once user scans QR and confirms
  role                VARCHAR(10) DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  failed_attempts     INTEGER DEFAULT 0,
  locked_until        TIMESTAMP,
  stripe_customer_id  BYTEA,                          -- pgp_sym_encrypt(cus_xxx, key)
  newsletter_opted_in BOOLEAN DEFAULT FALSE,
  created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Blog posts
-- ============================================================
CREATE TABLE posts (
  id                    SERIAL PRIMARY KEY,
  user_id               INTEGER REFERENCES users(id) ON DELETE CASCADE,
  title                 VARCHAR(200) NOT NULL,
  content               TEXT NOT NULL,
  pet_name              VARCHAR(100),
  pet_species           VARCHAR(50),
  image_filename        VARCHAR(255),
  donation_pool_enabled BOOLEAN DEFAULT FALSE,
  created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Comments on posts
-- ============================================================
CREATE TABLE comments (
  id         SERIAL PRIMARY KEY,
  post_id    INTEGER REFERENCES posts(id) ON DELETE CASCADE,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  content    TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Donations (Stripe-backed)
-- amount stored in pence (integer) to avoid floating-point issues
-- ============================================================
CREATE TABLE donations (
  id                       SERIAL PRIMARY KEY,
  user_id                  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  post_id                  INTEGER REFERENCES posts(id) ON DELETE SET NULL,
  amount                   INTEGER NOT NULL,
  currency                 VARCHAR(3) DEFAULT 'gbp',
  type                     VARCHAR(20) CHECK (type IN ('one-off', 'monthly')),
  stripe_payment_intent_id VARCHAR(255),
  stripe_subscription_id   VARCHAR(255),
  status                   VARCHAR(20) DEFAULT 'pending',
  created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Newsletter posts (created by admins, sent to opted-in users)
-- ============================================================
CREATE TABLE newsletter_posts (
  id            SERIAL PRIMARY KEY,
  admin_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  title         VARCHAR(200) NOT NULL,
  content       TEXT NOT NULL,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Audit log — records every admin action for accountability
-- ============================================================
CREATE TABLE audit_log (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action      VARCHAR(100) NOT NULL,
  target_type VARCHAR(50),
  target_id   INTEGER,
  ip_address  VARCHAR(45),
  timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Password reset tokens
-- token_hash stores bcrypt hash of the token sent via email
-- ============================================================
CREATE TABLE password_reset_tokens (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used       BOOLEAN DEFAULT FALSE
);
