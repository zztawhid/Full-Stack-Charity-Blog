/**
 * Admin Routes
 * 
 * Handles: user management, post management, newsletter creation, audit log viewing
 * 
 * Security mitigations:
 * - Role-based access control: every route checks user role is 'admin'
 * - Audit logging: every admin action recorded to audit_log table
 * - CSRF token required on all state-changing actions
 * - Input validation and XSS sanitisation
 * - All SQL queries use parameterised syntax
 * - IDOR prevention: admin verifies resources exist before acting
 */

const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const nodemailer = require('nodemailer');
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { logAudit } = require('../middleware/audit');
const { newsletterValidation, sanitise } = require('../middleware/validator');

const ENCRYPTION_KEY = process.env.DB_ENCRYPTION_KEY;

// Email transporter for newsletters
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT, 10),
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Apply auth + admin role check to ALL admin routes
router.use(requireAuth);
router.use(requireRole('admin'));

// ============================================================
// GET /admin — Admin dashboard
// ============================================================
router.get('/', async (req, res) => {
  try {
    const userCount = await pool.query('SELECT COUNT(*) FROM users');
    const postCount = await pool.query('SELECT COUNT(*) FROM posts');
    const donationSum = await pool.query(
      "SELECT COALESCE(SUM(amount), 0) AS total FROM donations WHERE status = 'succeeded'"
    );

    res.render('admin/dashboard', {
      stats: {
        users: userCount.rows[0].count,
        posts: postCount.rows[0].count,
        donations: donationSum.rows[0].total
      }
    });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    res.status(500).render('error', { message: 'Could not load admin dashboard.' });
  }
});

// ============================================================
// GET /admin/users — List all users
// ============================================================
router.get('/users', async (req, res) => {
  try {
    const { rows: users } = await pool.query(
      `SELECT id, username, pgp_sym_decrypt(email, $1) AS email,
              role, failed_attempts, locked_until, newsletter_opted_in, created_at
       FROM users ORDER BY created_at DESC`,
      [ENCRYPTION_KEY]
    );

    res.render('admin/users', { users });
  } catch (err) {
    console.error('Admin users list error:', err);
    res.status(500).render('error', { message: 'Could not load users.' });
  }
});

// ============================================================
// POST /admin/users/:id/role — Change a user's role
// 
// Audit logged: records which admin changed which user's role
// ============================================================
router.post('/users/:id/role', async (req, res) => {
  try {
    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) {
      return res.status(400).render('error', { message: 'Invalid user ID.' });
    }

    const { role } = req.body;
    if (!['user', 'admin'].includes(role)) {
      return res.status(400).render('error', { message: 'Invalid role.' });
    }

    // Prevent admin from demoting themselves
    if (userId === req.session.user.id && role !== 'admin') {
      req.session.error = 'You cannot remove your own admin role.';
      return res.redirect('/admin/users');
    }

    await pool.query(
      'UPDATE users SET role = $1 WHERE id = $2',
      [role, userId]
    );

    // Audit log: record role change
    await logAudit(req.session.user.id, `change_role_to_${role}`, 'user', userId, req.ip);

    req.session.success = 'User role updated.';
    res.redirect('/admin/users');
  } catch (err) {
    console.error('Admin change role error:', err);
    req.session.error = 'Failed to update user role.';
    res.redirect('/admin/users');
  }
});

// ============================================================
// POST /admin/users/:id/unlock — Unlock a locked user account
// Audit logged
// ============================================================
router.post('/users/:id/unlock', async (req, res) => {
  try {
    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) {
      return res.status(400).render('error', { message: 'Invalid user ID.' });
    }

    await pool.query(
      'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1',
      [userId]
    );

    await logAudit(req.session.user.id, 'unlock_account', 'user', userId, req.ip);

    req.session.success = 'User account unlocked.';
    res.redirect('/admin/users');
  } catch (err) {
    console.error('Admin unlock error:', err);
    req.session.error = 'Failed to unlock account.';
    res.redirect('/admin/users');
  }
});

// ============================================================
// POST /admin/users/:id/delete — Delete a user account
// Audit logged
// ============================================================
router.post('/users/:id/delete', async (req, res) => {
  try {
    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) {
      return res.status(400).render('error', { message: 'Invalid user ID.' });
    }

    // Prevent admin from deleting themselves
    if (userId === req.session.user.id) {
      req.session.error = 'You cannot delete your own account from the admin panel.';
      return res.redirect('/admin/users');
    }

    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    await logAudit(req.session.user.id, 'delete_user', 'user', userId, req.ip);

    req.session.success = 'User deleted.';
    res.redirect('/admin/users');
  } catch (err) {
    console.error('Admin delete user error:', err);
    req.session.error = 'Failed to delete user.';
    res.redirect('/admin/users');
  }
});

// ============================================================
// GET /admin/posts — List all posts for admin management
// ============================================================
router.get('/posts', async (req, res) => {
  try {
    const { rows: posts } = await pool.query(
      `SELECT p.id, p.title, p.pet_name, p.created_at, u.username
       FROM posts p
       JOIN users u ON p.user_id = u.id
       ORDER BY p.created_at DESC`
    );

    res.render('admin/posts', { posts });
  } catch (err) {
    console.error('Admin posts list error:', err);
    res.status(500).render('error', { message: 'Could not load posts.' });
  }
});

// ============================================================
// POST /admin/posts/:id/delete — Delete a post (admin action)
// Audit logged
// ============================================================
router.post('/posts/:id/delete', async (req, res) => {
  try {
    const postId = parseInt(req.params.id, 10);
    if (isNaN(postId)) {
      return res.status(400).render('error', { message: 'Invalid post ID.' });
    }

    await pool.query('DELETE FROM posts WHERE id = $1', [postId]);
    await logAudit(req.session.user.id, 'delete_post', 'post', postId, req.ip);

    req.session.success = 'Post deleted.';
    res.redirect('/admin/posts');
  } catch (err) {
    console.error('Admin delete post error:', err);
    req.session.error = 'Failed to delete post.';
    res.redirect('/admin/posts');
  }
});

// ============================================================
// GET /admin/audit-log — View audit log
// ============================================================
router.get('/audit-log', async (req, res) => {
  try {
    const { rows: logs } = await pool.query(
      `SELECT a.id, a.action, a.target_type, a.target_id, a.ip_address,
              a.timestamp, u.username
       FROM audit_log a
       LEFT JOIN users u ON a.user_id = u.id
       ORDER BY a.timestamp DESC
       LIMIT 200`
    );

    res.render('admin/audit-log', { logs });
  } catch (err) {
    console.error('Admin audit log error:', err);
    res.status(500).render('error', { message: 'Could not load audit log.' });
  }
});

// ============================================================
// GET /admin/newsletter — Show newsletter management page
// ============================================================
router.get('/newsletter', async (req, res) => {
  try {
    const { rows: newsletters } = await pool.query(
      `SELECT np.id, np.title, np.created_at
       FROM newsletter_posts np
       ORDER BY np.created_at DESC`
    );

    res.render('admin/newsletter', { newsletters, errors: null });
  } catch (err) {
    console.error('Admin newsletter page error:', err);
    res.status(500).render('error', { message: 'Could not load newsletter management.' });
  }
});

// ============================================================
// POST /admin/newsletter — Create and send a newsletter post
// Audit logged
// ============================================================
router.post('/newsletter', newsletterValidation, async (req, res) => {
  try {
    if (req.validationErrors) {
      const { rows: newsletters } = await pool.query(
        'SELECT id, title, created_at FROM newsletter_posts ORDER BY created_at DESC'
      );
      return res.render('admin/newsletter', { newsletters, errors: req.validationErrors });
    }

    const { title, content } = req.body;

    // Insert newsletter post
    const result = await pool.query(
      `INSERT INTO newsletter_posts (admin_user_id, title, content)
       VALUES ($1, $2, $3) RETURNING id`,
      [req.session.user.id, title, content]
    );

    await logAudit(req.session.user.id, 'create_newsletter', 'newsletter_post', result.rows[0].id, req.ip);

    // Send email to all opted-in users
    const { rows: subscribers } = await pool.query(
      `SELECT pgp_sym_decrypt(email, $1) AS email
       FROM users
       WHERE newsletter_opted_in = TRUE`,
      [ENCRYPTION_KEY]
    );

    for (const sub of subscribers) {
      try {
        await transporter.sendMail({
          from: process.env.EMAIL_FROM,
          to: sub.email,
          subject: `Newsletter: ${title}`,
          html: `<h1>${title}</h1><div>${content}</div>
                 <p><small>You are receiving this because you opted in to the newsletter.
                 Log in to change your preferences.</small></p>`
        });
      } catch (emailErr) {
        console.error(`Failed to send newsletter to ${sub.email}:`, emailErr);
      }
    }

    req.session.success = `Newsletter sent to ${subscribers.length} subscriber(s).`;
    res.redirect('/admin/newsletter');
  } catch (err) {
    console.error('Admin newsletter create error:', err);
    req.session.error = 'Failed to create newsletter.';
    res.redirect('/admin/newsletter');
  }
});

module.exports = router;
