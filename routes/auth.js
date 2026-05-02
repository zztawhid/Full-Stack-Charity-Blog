/**
 * Authentication Routes
 * 
 * Handles: registration, login (with TOTP MFA), logout, forgot/reset password
 * 
 * Security mitigations implemented here:
 * - Password hashing with bcrypt (salt rounds 12) + server-side pepper
 * - TOTP-based multi-factor authentication (speakeasy + qrcode)
 * - Account enumeration prevention (generic messages + timing-safe comparison)
 * - Account lockout after 10 failed attempts
 * - Session regeneration on login to prevent session fixation
 * - Rate limiting on login endpoint
 * - Input validation and XSS sanitisation
 * - All SQL queries use parameterised syntax
 */

const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcrypt');
const crypto   = require('crypto');
const speakeasy = require('speakeasy');
const QRCode   = require('qrcode');
const nodemailer = require('nodemailer');
const pool     = require('../db/pool');
const { requireAuth, requireGuest } = require('../middleware/auth');
const { loginLimiter } = require('../middleware/rateLimiter');
const {
  registerValidation,
  loginValidation,
  forgotPasswordValidation,
  resetPasswordValidation
} = require('../middleware/validator');

const SALT_ROUNDS = 12;
const ENCRYPTION_KEY = process.env.DB_ENCRYPTION_KEY;
const PEPPER = process.env.PEPPER;

// Dummy hash used for timing-safe comparison when user does not exist
// This ensures login takes the same time whether or not the username is valid
const DUMMY_HASH = bcrypt.hashSync('dummy_password_for_timing_safety', SALT_ROUNDS);

// Email transporter for password reset and account unlock emails
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT, 10),
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ============================================================
// GET /auth/register — Show registration form
// ============================================================
router.get('/register', requireGuest, (req, res) => {
  res.render('register', { errors: null });
});

// ============================================================
// POST /auth/register — Create new user account
// 
// Security:
// 1. Input validation (username, email, password strength)
// 2. Password is peppered then hashed with bcrypt (12 rounds)
// 3. Email is encrypted with pgp_sym_encrypt before storage
// 4. TOTP secret is generated and encrypted in the database
// 5. QR code is displayed for authenticator app setup
// ============================================================
router.post('/register', requireGuest, registerValidation, async (req, res) => {
  try {
    // Check for validation errors
    if (req.validationErrors) {
      return res.render('register', { errors: req.validationErrors });
    }

    const { username, email, password } = req.body;

    // Check if username already exists (parameterised query)
    const existing = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );
    if (existing.rows.length > 0) {
      return res.render('register', { errors: ['Username is already taken.'] });
    }

    /**
     * Password hashing with pepper:
     * 1. Append the server-side pepper to the user's password
     * 2. Hash the combined string with bcrypt (12 salt rounds)
     * The pepper adds an extra layer — even if the DB is compromised,
     * the attacker also needs the pepper from the .env to crack hashes.
     */
    const peppered = password + PEPPER;
    const passwordHash = await bcrypt.hash(peppered, SALT_ROUNDS);

    /**
     * Generate TOTP secret for multi-factor authentication.
     * The secret is encrypted before storage so a database breach
     * does not expose MFA secrets.
     */
    const totpSecret = speakeasy.generateSecret({
      name: `${process.env.TOTP_APP_NAME}:${username}`,
      issuer: process.env.TOTP_APP_NAME
    });

    // SHA-256 hash of email for lookup (forgot password)
    const emailHash = crypto
      .createHash('sha256')
      .update(email.toLowerCase().trim())
      .digest('hex');

    // Insert user with encrypted email and TOTP secret (parameterised query)
    const result = await pool.query(
      `INSERT INTO users (username, email, email_hash, password_hash, totp_secret, role)
       VALUES ($1, pgp_sym_encrypt($2, $3), $4, $5, pgp_sym_encrypt($6, $3), 'user')
       RETURNING id`,
      [username, email, ENCRYPTION_KEY, emailHash, passwordHash, totpSecret.base32]
    );

    // Generate QR code for authenticator app
    const qrDataUrl = await QRCode.toDataURL(totpSecret.otpauth_url);

    // Store user ID in session temporarily for MFA setup
    req.session.pendingMfaSetup = {
      userId: result.rows[0].id,
      username: username,
      totpSecret: totpSecret.base32
    };

    res.render('mfa-setup', {
      qrDataUrl,
      totpSecret: totpSecret.base32,
      username,
      errors: null
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.render('register', { errors: ['An error occurred during registration.'] });
  }
});

// ============================================================
// POST /auth/verify-mfa-setup — Confirm TOTP setup after registration
// User must enter a valid 6-digit code to prove they set up the app
// ============================================================
router.post('/verify-mfa-setup', async (req, res) => {
  try {
    const pending = req.session.pendingMfaSetup;
    if (!pending) {
      return res.redirect('/auth/register');
    }

    const { token } = req.body;

    const verified = speakeasy.totp.verify({
      secret: pending.totpSecret,
      encoding: 'base32',
      token: token,
      window: 1 // Allow 1 step tolerance (30 seconds each way)
    });

    if (!verified) {
      const qrSecret = speakeasy.generateSecret({
        name: `${process.env.TOTP_APP_NAME}:${pending.username}`,
        issuer: process.env.TOTP_APP_NAME
      });
      // Re-generate QR with the SAME secret
      const qrDataUrl = await QRCode.toDataURL(
        speakeasy.otpauthURL({
          secret: pending.totpSecret,
          encoding: 'base32',
          label: `${process.env.TOTP_APP_NAME}:${pending.username}`,
          issuer: process.env.TOTP_APP_NAME
        })
      );
      return res.render('mfa-setup', {
        qrDataUrl,
        totpSecret: pending.totpSecret,
        username: pending.username,
        errors: ['Invalid code. Please try again.']
      });
    }

    // Mark TOTP as verified in the database
    await pool.query(
      'UPDATE users SET totp_verified = TRUE WHERE id = $1',
      [pending.userId]
    );

    delete req.session.pendingMfaSetup;
    req.session.success = 'Registration complete! Please log in.';
    res.redirect('/auth/login');
  } catch (err) {
    console.error('MFA setup verification error:', err);
    res.redirect('/auth/register');
  }
});

// ============================================================
// GET /auth/login — Show login form
// ============================================================
router.get('/login', requireGuest, (req, res) => {
  res.render('login', { errors: null });
});

// ============================================================
// POST /auth/login — Authenticate user (step 1: credentials)
// 
// Account enumeration prevention:
// - Always returns the SAME generic error message whether the
//   username exists or not
// - Uses timing-safe comparison: if the user doesn't exist,
//   bcrypt.compare is still called against a dummy hash so the
//   response time is identical
// 
// Account lockout:
// - After ACCOUNT_LOCKOUT_THRESHOLD (10) failed attempts, the
//   account is locked and an unlock email is sent
// ============================================================
router.post('/login', requireGuest, loginLimiter, loginValidation, async (req, res) => {
  // Generic message returned for ALL login failures to prevent account enumeration
  const GENERIC_ERROR = 'Invalid username or password.';

  try {
    if (req.validationErrors) {
      return res.render('login', { errors: [GENERIC_ERROR] });
    }

    const { username, password } = req.body;

    // Look up user by username (parameterised query)
    const result = await pool.query(
      `SELECT id, username, password_hash, role, failed_attempts, locked_until,
              totp_verified
       FROM users WHERE username = $1`,
      [username]
    );

    const user = result.rows[0];

    /**
     * Timing-safe comparison:
     * If the user does not exist, we still run bcrypt.compare against
     * a dummy hash. This ensures the response time is the same whether
     * the username is valid or not, preventing timing-based enumeration.
     */
    const hashToCompare = user ? user.password_hash : DUMMY_HASH;
    const peppered = password + PEPPER;
    const passwordValid = await bcrypt.compare(peppered, hashToCompare);

    // If user doesn't exist or password is wrong, return generic error
    if (!user || !passwordValid) {
      // Increment failed attempts if user exists
      if (user) {
        const newAttempts = user.failed_attempts + 1;
        const lockoutThreshold = parseInt(process.env.ACCOUNT_LOCKOUT_THRESHOLD, 10) || 10;

        if (newAttempts >= lockoutThreshold) {
          /**
           * Account lockout:
           * Lock the account for 30 minutes after too many failed attempts.
           * Send an unlock email with a token.
           */
          const lockUntil = new Date(Date.now() + 30 * 60 * 1000);
          await pool.query(
            'UPDATE users SET failed_attempts = $1, locked_until = $2 WHERE id = $3',
            [newAttempts, lockUntil, user.id]
          );

          // Generate unlock token and send email
          await sendUnlockEmail(user.id);

          return res.render('login', {
            errors: ['Account locked due to too many failed attempts. Check your email for unlock instructions.']
          });
        } else {
          await pool.query(
            'UPDATE users SET failed_attempts = $1 WHERE id = $2',
            [newAttempts, user.id]
          );
        }
      }

      return res.render('login', { errors: [GENERIC_ERROR] });
    }

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.render('login', {
        errors: ['Account is temporarily locked. Please check your email or try again later.']
      });
    }

    // Check if TOTP is set up and verified
    if (!user.totp_verified) {
      return res.render('login', { errors: ['MFA setup incomplete. Please contact support.'] });
    }

    // Store pending login in session for MFA step
    req.session.pendingLogin = {
      userId: user.id,
      username: user.username,
      role: user.role
    };

    res.render('mfa-verify', { errors: null });
  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { errors: ['An error occurred. Please try again.'] });
  }
});

// ============================================================
// POST /auth/verify-mfa — Verify TOTP code (step 2 of login)
// 
// After password is validated, the user must provide a valid
// 6-digit TOTP code from their authenticator app.
// The TOTP secret is decrypted from the database for verification.
// ============================================================
router.post('/verify-mfa', async (req, res) => {
  try {
    const pending = req.session.pendingLogin;
    if (!pending) {
      return res.redirect('/auth/login');
    }

    const { token } = req.body;

    // Decrypt the TOTP secret from the database (parameterised query)
    const result = await pool.query(
      'SELECT pgp_sym_decrypt(totp_secret, $1) AS totp_secret FROM users WHERE id = $2',
      [ENCRYPTION_KEY, pending.userId]
    );

    if (result.rows.length === 0) {
      return res.redirect('/auth/login');
    }

    const totpSecret = result.rows[0].totp_secret;

    /**
     * TOTP verification using speakeasy:
     * - Checks the 6-digit code against the user's secret
     * - window: 1 allows a 30-second tolerance on either side
     * - If the code is invalid, the login is rejected
     */
    const verified = speakeasy.totp.verify({
      secret: totpSecret,
      encoding: 'base32',
      token: token,
      window: 1
    });

    if (!verified) {
      return res.render('mfa-verify', { errors: ['Invalid authentication code. Please try again.'] });
    }

    // Reset failed attempts on successful login
    await pool.query(
      'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1',
      [pending.userId]
    );

    /**
     * Session regeneration on login:
     * Generates a new session ID after authentication to prevent
     * session fixation attacks. The old session ID is invalidated.
     */
    const pendingData = { ...pending };
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.render('login', { errors: ['An error occurred. Please try again.'] });
      }

      // Set authenticated user in the new session
      req.session.user = {
        id: pendingData.userId,
        username: pendingData.username,
        role: pendingData.role
      };

      // Re-bind User-Agent to new session
      req.session._ua = req.headers['user-agent'] || '';

      req.session.save((err) => {
        if (err) console.error('Session save error:', err);
        res.redirect('/');
      });
    });
  } catch (err) {
    console.error('MFA verification error:', err);
    res.redirect('/auth/login');
  }
});

// ============================================================
// GET /auth/logout — Destroy session and redirect to home
// ============================================================
router.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err);
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});

// ============================================================
// GET /auth/forgot-password — Show forgot password form
// ============================================================
router.get('/forgot-password', requireGuest, (req, res) => {
  res.render('forgot-password', { errors: null, info: null });
});

// ============================================================
// POST /auth/forgot-password — Send password reset email
// 
// Account enumeration prevention:
// - Always shows the SAME success message whether the email
//   exists or not, so attackers cannot determine valid emails
// ============================================================
router.post('/forgot-password', requireGuest, forgotPasswordValidation, async (req, res) => {
  // Always show the same message regardless of whether email was found
  const GENERIC_MSG = 'If an account with that email exists, a password reset link has been sent.';

  try {
    if (req.validationErrors) {
      return res.render('forgot-password', { errors: req.validationErrors, info: null });
    }

    const { email } = req.body;
    const emailHash = crypto
      .createHash('sha256')
      .update(email.toLowerCase().trim())
      .digest('hex');

    // Look up user by email hash (parameterised query)
    const result = await pool.query(
      'SELECT id FROM users WHERE email_hash = $1',
      [emailHash]
    );

    if (result.rows.length > 0) {
      const userId = result.rows[0].id;

      // Generate a secure random token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const tokenHash = await bcrypt.hash(resetToken, SALT_ROUNDS);
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      // Store the hashed token in the database (parameterised query)
      await pool.query(
        `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
         VALUES ($1, $2, $3)`,
        [userId, tokenHash, expiresAt]
      );

      // Send reset email
      const resetUrl = `http://localhost:${process.env.PORT}/auth/reset-password?token=${resetToken}&uid=${userId}`;
      await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to: email,
        subject: 'Password Reset — Animal Charity Blog',
        html: `<p>Click the link below to reset your password:</p>
               <p><a href="${resetUrl}">${resetUrl}</a></p>
               <p>This link expires in 1 hour.</p>`
      });
    }

    // Always show the same message (account enumeration prevention)
    res.render('forgot-password', { errors: null, info: GENERIC_MSG });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.render('forgot-password', { errors: null, info: GENERIC_MSG });
  }
});

// ============================================================
// GET /auth/reset-password — Show reset password form
// ============================================================
router.get('/reset-password', requireGuest, (req, res) => {
  const { token, uid } = req.query;
  if (!token || !uid) {
    return res.redirect('/auth/forgot-password');
  }
  res.render('reset-password', { token, uid, errors: null });
});

// ============================================================
// POST /auth/reset-password — Process password reset
// ============================================================
router.post('/reset-password', requireGuest, resetPasswordValidation, async (req, res) => {
  try {
    const { token, uid, password } = req.body;

    if (req.validationErrors) {
      return res.render('reset-password', { token, uid, errors: req.validationErrors });
    }

    // Find valid (unused, not expired) reset tokens for this user
    const result = await pool.query(
      `SELECT id, token_hash FROM password_reset_tokens
       WHERE user_id = $1 AND used = FALSE AND expires_at > NOW()
       ORDER BY id DESC`,
      [uid]
    );

    let tokenValid = false;
    let tokenId = null;

    // Check each token (there might be multiple pending)
    for (const row of result.rows) {
      const match = await bcrypt.compare(token, row.token_hash);
      if (match) {
        tokenValid = true;
        tokenId = row.id;
        break;
      }
    }

    if (!tokenValid) {
      return res.render('reset-password', {
        token, uid,
        errors: ['Invalid or expired reset link. Please request a new one.']
      });
    }

    // Hash new password with pepper
    const peppered = password + PEPPER;
    const passwordHash = await bcrypt.hash(peppered, SALT_ROUNDS);

    // Update password and mark token as used (parameterised queries)
    await pool.query(
      'UPDATE users SET password_hash = $1, failed_attempts = 0, locked_until = NULL WHERE id = $2',
      [passwordHash, uid]
    );
    await pool.query(
      'UPDATE password_reset_tokens SET used = TRUE WHERE id = $1',
      [tokenId]
    );

    req.session.success = 'Password reset successfully. Please log in with your new password.';
    res.redirect('/auth/login');
  } catch (err) {
    console.error('Reset password error:', err);
    res.render('reset-password', {
      token: req.body.token, uid: req.body.uid,
      errors: ['An error occurred. Please try again.']
    });
  }
});

// ============================================================
// GET /auth/unlock — Unlock a locked account via email token
// ============================================================
router.get('/unlock', async (req, res) => {
  try {
    const { token, uid } = req.query;
    if (!token || !uid) {
      return res.redirect('/auth/login');
    }

    // Find the reset token (reusing password_reset_tokens table)
    const result = await pool.query(
      `SELECT id, token_hash FROM password_reset_tokens
       WHERE user_id = $1 AND used = FALSE AND expires_at > NOW()
       ORDER BY id DESC`,
      [uid]
    );

    let tokenValid = false;
    let tokenId = null;

    for (const row of result.rows) {
      const match = await bcrypt.compare(token, row.token_hash);
      if (match) {
        tokenValid = true;
        tokenId = row.id;
        break;
      }
    }

    if (!tokenValid) {
      req.session.error = 'Invalid or expired unlock link.';
      return res.redirect('/auth/login');
    }

    // Unlock the account
    await pool.query(
      'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1',
      [uid]
    );
    await pool.query(
      'UPDATE password_reset_tokens SET used = TRUE WHERE id = $1',
      [tokenId]
    );

    req.session.success = 'Account unlocked successfully. Please log in.';
    res.redirect('/auth/login');
  } catch (err) {
    console.error('Unlock error:', err);
    req.session.error = 'An error occurred. Please try again.';
    res.redirect('/auth/login');
  }
});

// ============================================================
// Helper: Send account unlock email
// ============================================================
async function sendUnlockEmail(userId) {
  try {
    const result = await pool.query(
      'SELECT pgp_sym_decrypt(email, $1) AS email FROM users WHERE id = $2',
      [ENCRYPTION_KEY, userId]
    );

    if (result.rows.length === 0) return;

    const email = result.rows[0].email;
    const unlockToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = await bcrypt.hash(unlockToken, SALT_ROUNDS);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    await pool.query(
      `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [userId, tokenHash, expiresAt]
    );

    const unlockUrl = `http://localhost:${process.env.PORT}/auth/unlock?token=${unlockToken}&uid=${userId}`;
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Account Locked — Animal Charity Blog',
      html: `<p>Your account has been locked due to too many failed login attempts.</p>
             <p>Click the link below to unlock your account:</p>
             <p><a href="${unlockUrl}">${unlockUrl}</a></p>
             <p>This link expires in 1 hour.</p>`
    });
  } catch (err) {
    console.error('Send unlock email error:', err);
  }
}

module.exports = router;
