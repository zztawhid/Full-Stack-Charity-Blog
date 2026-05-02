/**
 * Blog Routes
 * 
 * Handles: listing posts, viewing individual posts, creating, editing, deleting posts
 * 
 * Security mitigations:
 * - IDOR prevention: edit/delete checks that the post belongs to the requesting user
 * - Input validation and XSS sanitisation on all form inputs
 * - File upload security: MIME type validation, UUID renaming, size limit
 * - All SQL queries use parameterised syntax ($1, $2, etc.)
 * - CSRF token required on all state-changing requests
 */

const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const { requireAuth } = require('../middleware/auth');
const { upload, validateAndSaveFile } = require('../middleware/upload');
const { postValidation, sanitise } = require('../middleware/validator');

// ============================================================
// GET /blog/search — Search posts by title, content, or pet name
//
// Security:
// - Query parameter sanitised with xss library before use
// - Parameterised ILIKE query — user input NEVER concatenated into SQL
//   The % wildcards are added server-side, not by the user
// - Route placed BEFORE /:id to prevent Express routing it as a post ID
// ============================================================
router.get('/search', async (req, res) => {
  const raw = typeof req.query.q === 'string' ? req.query.q.trim() : '';

  if (!raw) {
    return res.redirect('/blog');
  }

  const q = sanitise(raw);

  try {
    const { rows: posts } = await pool.query(
      `SELECT p.id, p.title, p.pet_name, p.pet_species, p.image_filename,
              LEFT(p.content, 200) AS excerpt, p.created_at, u.username
       FROM posts p
       JOIN users u ON p.user_id = u.id
       WHERE p.title ILIKE $1
          OR p.content ILIKE $1
          OR p.pet_name ILIKE $1
       ORDER BY p.created_at DESC`,
      [`%${q}%`]
    );
    res.render('blog', { posts, searchQuery: q, isSearch: true });
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).render('error', { message: 'Search failed.' });
  }
});

// ============================================================
// GET /blog — List all blog posts
// ============================================================
router.get('/', async (req, res) => {
  try {
    const { rows: posts } = await pool.query(
      `SELECT p.id, p.title, p.pet_name, p.pet_species, p.image_filename,
              LEFT(p.content, 200) AS excerpt, p.created_at, u.username
       FROM posts p
       JOIN users u ON p.user_id = u.id
       ORDER BY p.created_at DESC`
    );
    res.render('blog', { posts });
  } catch (err) {
    console.error('Blog list error:', err);
    res.status(500).render('error', { message: 'Could not load blog posts.' });
  }
});

// ============================================================
// GET /blog/create — Show create post form (auth required)
// ============================================================
router.get('/create', requireAuth, (req, res) => {
  res.render('create-post', { errors: null, post: {} });
});

// ============================================================
// POST /blog/create — Create a new blog post
// 
// Security:
// - requireAuth ensures only logged-in users can post
// - Input validation and XSS sanitisation via postValidation
// - File upload validated (MIME type check, UUID rename, size limit)
// - CSRF token validated by global middleware
// ============================================================
router.post('/create', requireAuth, upload.single('image'), postValidation, async (req, res) => {
  try {
    if (req.validationErrors) {
      return res.render('create-post', { errors: req.validationErrors, post: req.body });
    }

    const { title, content, pet_name, pet_species, donation_pool_enabled } = req.body;
    let imageFilename = null;

    // Validate and save uploaded image (if present)
    if (req.file) {
      try {
        imageFilename = await validateAndSaveFile(req.file);
      } catch (uploadErr) {
        return res.render('create-post', { errors: [uploadErr.message], post: req.body });
      }
    }

    // Insert post with parameterised query — zero string concatenation
    await pool.query(
      `INSERT INTO posts (user_id, title, content, pet_name, pet_species, image_filename, donation_pool_enabled)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        req.session.user.id,
        title,
        content,
        pet_name || null,
        pet_species || null,
        imageFilename,
        donation_pool_enabled === 'on'
      ]
    );

    req.session.success = 'Post created successfully!';
    res.redirect('/blog');
  } catch (err) {
    console.error('Create post error:', err);
    res.render('create-post', { errors: ['Failed to create post.'], post: req.body });
  }
});

// ============================================================
// GET /blog/:id — View a single blog post with comments
// ============================================================
router.get('/:id', async (req, res) => {
  try {
    const postId = parseInt(req.params.id, 10);
    if (isNaN(postId)) {
      return res.status(400).render('error', { message: 'Invalid post ID.' });
    }

    // Fetch post with author info (parameterised query)
    const postResult = await pool.query(
      `SELECT p.*, u.username
       FROM posts p
       JOIN users u ON p.user_id = u.id
       WHERE p.id = $1`,
      [postId]
    );

    if (postResult.rows.length === 0) {
      return res.status(404).render('error', { message: 'Post not found.' });
    }

    // Fetch comments for this post (parameterised query)
    const commentsResult = await pool.query(
      `SELECT c.*, u.username
       FROM comments c
       JOIN users u ON c.user_id = u.id
       WHERE c.post_id = $1
       ORDER BY c.created_at ASC`,
      [postId]
    );

    // Fetch total donations for this post
    const donationResult = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total
       FROM donations
       WHERE post_id = $1 AND status = 'succeeded'`,
      [postId]
    );

    res.render('post', {
      post: postResult.rows[0],
      comments: commentsResult.rows,
      donationTotal: donationResult.rows[0].total
    });
  } catch (err) {
    console.error('View post error:', err);
    res.status(500).render('error', { message: 'Could not load the post.' });
  }
});

// ============================================================
// GET /blog/:id/edit — Show edit post form
// 
// IDOR prevention: checks that the post belongs to the requesting
// user before allowing access to the edit form.
// ============================================================
router.get('/:id/edit', requireAuth, async (req, res) => {
  try {
    const postId = parseInt(req.params.id, 10);
    if (isNaN(postId)) {
      return res.status(400).render('error', { message: 'Invalid post ID.' });
    }

    const result = await pool.query(
      'SELECT * FROM posts WHERE id = $1',
      [postId]
    );

    if (result.rows.length === 0) {
      return res.status(404).render('error', { message: 'Post not found.' });
    }

    const post = result.rows[0];

    /**
     * IDOR prevention:
     * Verify the post belongs to the current user OR the user is an admin.
     * Without this check, any authenticated user could edit any post
     * by changing the ID in the URL.
     */
    if (post.user_id !== req.session.user.id && req.session.user.role !== 'admin') {
      return res.status(403).render('error', { message: 'You do not have permission to edit this post.' });
    }

    res.render('edit-post', { post, errors: null });
  } catch (err) {
    console.error('Edit post form error:', err);
    res.status(500).render('error', { message: 'Could not load the post for editing.' });
  }
});

// ============================================================
// POST /blog/:id/edit — Update a blog post
// 
// IDOR prevention + input validation + file upload security
// ============================================================
router.post('/:id/edit', requireAuth, upload.single('image'), postValidation, async (req, res) => {
  try {
    const postId = parseInt(req.params.id, 10);
    if (isNaN(postId)) {
      return res.status(400).render('error', { message: 'Invalid post ID.' });
    }

    // IDOR check: fetch post and verify ownership
    const existing = await pool.query(
      'SELECT * FROM posts WHERE id = $1',
      [postId]
    );

    if (existing.rows.length === 0) {
      return res.status(404).render('error', { message: 'Post not found.' });
    }

    const post = existing.rows[0];

    // IDOR prevention: only the owner or admin can edit
    if (post.user_id !== req.session.user.id && req.session.user.role !== 'admin') {
      return res.status(403).render('error', { message: 'You do not have permission to edit this post.' });
    }

    if (req.validationErrors) {
      return res.render('edit-post', { post: { ...post, ...req.body }, errors: req.validationErrors });
    }

    const { title, content, pet_name, pet_species, donation_pool_enabled } = req.body;
    let imageFilename = post.image_filename;

    if (req.file) {
      try {
        imageFilename = await validateAndSaveFile(req.file);
      } catch (uploadErr) {
        return res.render('edit-post', { post: { ...post, ...req.body }, errors: [uploadErr.message] });
      }
    }

    // Update post with parameterised query
    await pool.query(
      `UPDATE posts SET title = $1, content = $2, pet_name = $3, pet_species = $4,
       image_filename = $5, donation_pool_enabled = $6, updated_at = NOW()
       WHERE id = $7`,
      [title, content, pet_name || null, pet_species || null, imageFilename, donation_pool_enabled === 'on', postId]
    );

    req.session.success = 'Post updated successfully!';
    res.redirect(`/blog/${postId}`);
  } catch (err) {
    console.error('Edit post error:', err);
    res.status(500).render('error', { message: 'Failed to update the post.' });
  }
});

// ============================================================
// POST /blog/:id/delete — Delete a blog post
// 
// IDOR prevention: only the post owner or an admin can delete.
// ============================================================
router.post('/:id/delete', requireAuth, async (req, res) => {
  try {
    const postId = parseInt(req.params.id, 10);
    if (isNaN(postId)) {
      return res.status(400).render('error', { message: 'Invalid post ID.' });
    }

    const result = await pool.query(
      'SELECT user_id FROM posts WHERE id = $1',
      [postId]
    );

    if (result.rows.length === 0) {
      return res.status(404).render('error', { message: 'Post not found.' });
    }

    // IDOR prevention: verify ownership before deletion
    if (result.rows[0].user_id !== req.session.user.id && req.session.user.role !== 'admin') {
      return res.status(403).render('error', { message: 'You do not have permission to delete this post.' });
    }

    await pool.query('DELETE FROM posts WHERE id = $1', [postId]);

    req.session.success = 'Post deleted successfully.';
    res.redirect('/blog');
  } catch (err) {
    console.error('Delete post error:', err);
    res.status(500).render('error', { message: 'Failed to delete the post.' });
  }
});

module.exports = router;
