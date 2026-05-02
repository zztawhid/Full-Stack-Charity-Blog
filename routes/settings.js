/**
 * Settings Routes
 * 
 * Handles: change password, change email, delete account
 * 
 * Security mitigations:
 * - Re-authentication: current password required for ALL changes
 * - Password strength enforcement on change
 * - Password hashing with bcrypt + pepper
 * - Email encrypted with pgp_sym_encrypt on change
 * - IDOR prevention: users can only modify their own account
 * - Input validation on all fields
 * - CSRF token required on all forms
 * - All SQL queries use parameterised syntax
 */

const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcrypt');
const crypto  = require('crypto');
const pool    = require('../db/pool');
const { requireAuth } = require('../middleware/auth');
const {
  passwordChangeValidation,
  emailChangeValidation
} = require('../middleware/validator');

const SALT_ROUNDS = 12;
const ENCRYPTION_KEY = process.env.DB_ENCRYPTION_KEY;
const PEPPER = process.env.PEPPER;

// ============================================================
// GET /settings — Show settings page
// ============================================================
router.get('/', requireAuth, async (req, res) => {
  try {
    // Decrypt email for display
    const result = await pool.query(
      `SELECT username, pgp_sym_decrypt(email, $1) AS email, newsletter_opted_in
       FROM users WHERE id = $2`,
      [ENCRYPTION_KEY, req.session.user.id]
    );

    if (result.rows.length === 0) {
      return res.redirect('/auth/login');
    }

    res.render('settings', {
      profile: result.rows[0],
      errors: null,
      section: null
    });
  } catch (err) {
    console.error('Settings page error:', err);
    res.status(500).render('error', { message: 'Could not load settings.' });
  }
});

// ============================================================
// POST /settings/change-password — Change user's password
// 
// Re-authentication: requires current password before changing.
// This prevents an attacker who gains temporary access to the
// session from permanently taking over the account.
// 
// Password strength: enforced server-side (min 8 chars, 1 upper,
// 1 number, 1 symbol) to prevent weak passwords even if the
// client-side check is bypassed.
// ============================================================
router.post('/change-password', requireAuth, passwordChangeValidation, async (req, res) => {
  try {
    if (req.validationErrors) {
      const profile = await getUserProfile(req.session.user.id);
      return res.render('settings', { profile, errors: req.validationErrors, section: 'password' });
    }

    const { currentPassword, newPassword } = req.body;

    // Fetch current password hash for re-authentication
    const result = await pool.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [req.session.user.id]
    );

    if (result.rows.length === 0) {
      return res.redirect('/auth/login');
    }

    /**
     * Re-authentication:
     * Verify the current password before allowing any change.
     * This ensures that even if a session is hijacked, the attacker
     * cannot change the password without knowing the current one.
     */
    const peppered = currentPassword + PEPPER;
    const isValid = await bcrypt.compare(peppered, result.rows[0].password_hash);

    if (!isValid) {
      const profile = await getUserProfile(req.session.user.id);
      return res.render('settings', {
        profile,
        errors: ['Current password is incorrect.'],
        section: 'password'
      });
    }

    // Hash the new password with pepper
    const newPeppered = newPassword + PEPPER;
    const newHash = await bcrypt.hash(newPeppered, SALT_ROUNDS);

    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [newHash, req.session.user.id]
    );

    req.session.success = 'Password changed successfully.';
    res.redirect('/settings');
  } catch (err) {
    console.error('Change password error:', err);
    const profile = await getUserProfile(req.session.user.id);
    res.render('settings', { profile, errors: ['Failed to change password.'], section: 'password' });
  }
});

// ============================================================
// POST /settings/change-email — Change user's email
// 
// Re-authentication required. New email is encrypted before storage.
// ============================================================
router.post('/change-email', requireAuth, emailChangeValidation, async (req, res) => {
  try {
    if (req.validationErrors) {
      const profile = await getUserProfile(req.session.user.id);
      return res.render('settings', { profile, errors: req.validationErrors, section: 'email' });
    }

    const { currentPassword, newEmail } = req.body;

    // Re-authenticate
    const result = await pool.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [req.session.user.id]
    );

    const peppered = currentPassword + PEPPER;
    const isValid = await bcrypt.compare(peppered, result.rows[0].password_hash);

    if (!isValid) {
      const profile = await getUserProfile(req.session.user.id);
      return res.render('settings', {
        profile,
        errors: ['Current password is incorrect.'],
        section: 'email'
      });
    }

    // Hash new email for lookups
    const emailHash = crypto
      .createHash('sha256')
      .update(newEmail.toLowerCase().trim())
      .digest('hex');

    // Update email (encrypted) and email_hash
    await pool.query(
      `UPDATE users SET email = pgp_sym_encrypt($1, $2), email_hash = $3 WHERE id = $4`,
      [newEmail, ENCRYPTION_KEY, emailHash, req.session.user.id]
    );

    req.session.success = 'Email updated successfully.';
    res.redirect('/settings');
  } catch (err) {
    console.error('Change email error:', err);
    const profile = await getUserProfile(req.session.user.id);
    res.render('settings', { profile, errors: ['Failed to change email.'], section: 'email' });
  }
});

// ============================================================
// POST /settings/delete-account — Delete user's own account
// 
// Re-authentication required. Deletes the user and all associated
// data (posts, comments) via CASCADE in the database schema.
// ============================================================
router.post('/delete-account', requireAuth, async (req, res) => {
  try {
    const { currentPassword } = req.body;

    if (!currentPassword) {
      const profile = await getUserProfile(req.session.user.id);
      return res.render('settings', {
        profile,
        errors: ['Current password is required to delete your account.'],
        section: 'delete'
      });
    }

    const result = await pool.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [req.session.user.id]
    );

    const peppered = currentPassword + PEPPER;
    const isValid = await bcrypt.compare(peppered, result.rows[0].password_hash);

    if (!isValid) {
      const profile = await getUserProfile(req.session.user.id);
      return res.render('settings', {
        profile,
        errors: ['Current password is incorrect.'],
        section: 'delete'
      });
    }

    // Delete user (CASCADE removes posts, comments, etc.)
    await pool.query('DELETE FROM users WHERE id = $1', [req.session.user.id]);

    // Destroy session
    req.session.destroy((err) => {
      if (err) console.error('Session destroy error:', err);
      res.clearCookie('connect.sid');
      res.redirect('/');
    });
  } catch (err) {
    console.error('Delete account error:', err);
    const profile = await getUserProfile(req.session.user.id);
    res.render('settings', { profile, errors: ['Failed to delete account.'], section: 'delete' });
  }
});

// ============================================================
// Helper: Get user profile for re-rendering settings page
// ============================================================
async function getUserProfile(userId) {
  const result = await pool.query(
    `SELECT username, pgp_sym_decrypt(email, $1) AS email, newsletter_opted_in
     FROM users WHERE id = $2`,
    [ENCRYPTION_KEY, userId]
  );
  return result.rows[0] || {};
}

module.exports = router;
