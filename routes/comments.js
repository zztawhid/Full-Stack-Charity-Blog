/**
 * Comment Routes
 * 
 * Handles: adding and deleting comments on blog posts
 * 
 * Security mitigations:
 * - Authentication required to comment
 * - Input validation and XSS sanitisation
 * - IDOR prevention on delete (only comment owner or admin)
 * - Parameterised SQL queries
 * - CSRF token required
 */

const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const { requireAuth } = require('../middleware/auth');
const { commentValidation } = require('../middleware/validator');

// ============================================================
// POST /blog/:id/comment — Add a comment to a blog post
// 
// Security:
// - requireAuth ensures only logged-in users can comment
// - commentValidation sanitises content to prevent stored XSS
// - Parameterised query prevents SQL injection
// ============================================================
router.post('/:id/comment', requireAuth, commentValidation, async (req, res) => {
  try {
    const postId = parseInt(req.params.id, 10);
    if (isNaN(postId)) {
      return res.status(400).render('error', { message: 'Invalid post ID.' });
    }

    if (req.validationErrors) {
      req.session.error = req.validationErrors.join(', ');
      return res.redirect(`/blog/${postId}`);
    }

    const { content } = req.body;

    // Verify the post exists before adding a comment
    const postCheck = await pool.query('SELECT id FROM posts WHERE id = $1', [postId]);
    if (postCheck.rows.length === 0) {
      return res.status(404).render('error', { message: 'Post not found.' });
    }

    // Insert comment with parameterised query
    await pool.query(
      'INSERT INTO comments (post_id, user_id, content) VALUES ($1, $2, $3)',
      [postId, req.session.user.id, content]
    );

    res.redirect(`/blog/${postId}`);
  } catch (err) {
    console.error('Add comment error:', err);
    req.session.error = 'Failed to add comment.';
    res.redirect(`/blog/${req.params.id}`);
  }
});

// ============================================================
// POST /blog/:postId/comment/:commentId/delete — Delete a comment
// 
// IDOR prevention: only the comment owner or admin can delete.
// ============================================================
router.post('/:postId/comment/:commentId/delete', requireAuth, async (req, res) => {
  try {
    const postId = parseInt(req.params.postId, 10);
    const commentId = parseInt(req.params.commentId, 10);

    if (isNaN(postId) || isNaN(commentId)) {
      return res.status(400).render('error', { message: 'Invalid ID.' });
    }

    // Fetch comment to verify ownership (parameterised query)
    const result = await pool.query(
      'SELECT user_id FROM comments WHERE id = $1 AND post_id = $2',
      [commentId, postId]
    );

    if (result.rows.length === 0) {
      return res.status(404).render('error', { message: 'Comment not found.' });
    }

    /**
     * IDOR prevention:
     * Verify the comment belongs to the current user OR the user is an admin.
     * Without this, any user could delete any comment by guessing IDs.
     */
    if (result.rows[0].user_id !== req.session.user.id && req.session.user.role !== 'admin') {
      return res.status(403).render('error', { message: 'You do not have permission to delete this comment.' });
    }

    await pool.query('DELETE FROM comments WHERE id = $1', [commentId]);

    res.redirect(`/blog/${postId}`);
  } catch (err) {
    console.error('Delete comment error:', err);
    req.session.error = 'Failed to delete comment.';
    res.redirect(`/blog/${req.params.postId}`);
  }
});

module.exports = router;
