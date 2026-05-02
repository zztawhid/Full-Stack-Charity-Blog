/**
 * Newsletter Routes
 * 
 * Handles: viewing newsletter posts, opting in/out of newsletter
 * 
 * Security mitigations:
 * - Authentication required for opt-in/out actions
 * - CSRF token required on all form submissions
 * - Input validated and sanitised
 * - All SQL queries use parameterised syntax
 */

const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const { requireAuth } = require('../middleware/auth');

// ============================================================
// GET /newsletter — Show newsletter page with posts and opt-in toggle
// ============================================================
router.get('/', async (req, res) => {
  try {
    // Fetch published newsletter posts
    const { rows: newsletters } = await pool.query(
      `SELECT np.id, np.title, np.content, np.created_at, u.username AS author
       FROM newsletter_posts np
       LEFT JOIN users u ON np.admin_user_id = u.id
       ORDER BY np.created_at DESC`
    );

    // Check if user is opted in (if logged in)
    let isOptedIn = false;
    if (req.session && req.session.user) {
      const result = await pool.query(
        'SELECT newsletter_opted_in FROM users WHERE id = $1',
        [req.session.user.id]
      );
      if (result.rows.length > 0) {
        isOptedIn = result.rows[0].newsletter_opted_in;
      }
    }

    res.render('newsletter', { newsletters, isOptedIn });
  } catch (err) {
    console.error('Newsletter page error:', err);
    res.status(500).render('error', { message: 'Could not load newsletter.' });
  }
});

// ============================================================
// POST /newsletter/toggle — Toggle newsletter opt-in/out
// 
// Security:
// - requireAuth: only logged-in users can change preference
// - CSRF token validated by global middleware
// - Parameterised query to update the preference
// ============================================================
router.post('/toggle', requireAuth, async (req, res) => {
  try {
    // Toggle the current value
    await pool.query(
      'UPDATE users SET newsletter_opted_in = NOT newsletter_opted_in WHERE id = $1',
      [req.session.user.id]
    );

    const result = await pool.query(
      'SELECT newsletter_opted_in FROM users WHERE id = $1',
      [req.session.user.id]
    );

    const newStatus = result.rows[0].newsletter_opted_in;
    req.session.success = newStatus
      ? 'You have opted in to the newsletter.'
      : 'You have opted out of the newsletter.';

    res.redirect('/newsletter');
  } catch (err) {
    console.error('Newsletter toggle error:', err);
    req.session.error = 'Failed to update newsletter preference.';
    res.redirect('/newsletter');
  }
});

module.exports = router;
