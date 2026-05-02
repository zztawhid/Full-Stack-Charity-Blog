/**
 * Animal Charity Blog — Main Server Entry Point
 * 
 * Security layers applied in order:
 * 1. Helmet (security headers including CSP, HSTS, X-Frame-Options)
 * 2. Express-session with connect-pg-simple (server-side sessions)
 * 3. CSRF protection via csurf on all state-changing requests
 * 4. Rate limiting on authentication endpoints
 * 5. Input validation and XSS sanitisation on all user input
 * 6. Parameterised SQL queries throughout — zero string concatenation
 */

require('dotenv').config();

const express       = require('express');
const session       = require('express-session');
const PgSession     = require('connect-pg-simple')(session);
const crypto        = require('crypto');
const cookieParser  = require('cookie-parser');
const path          = require('path');
const fs            = require('fs');
const pool          = require('./db/pool');

// Middleware imports
const helmetConfig  = require('./middleware/helmet');
const csrfProtection = require('./middleware/csrf');
const { sessionGuard } = require('./middleware/sessionGuard');

// Route imports
const authRoutes       = require('./routes/auth');
const blogRoutes       = require('./routes/blog');
const commentRoutes    = require('./routes/comments');
const donationRoutes   = require('./routes/donations');
const newsletterRoutes = require('./routes/newsletter');
const settingsRoutes   = require('./routes/settings');
const adminRoutes      = require('./routes/admin');

const app = express();

// ============================================================
// Ensure upload directory exists
// ============================================================
const uploadDir = path.join(__dirname, process.env.UPLOAD_DIR || 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// ============================================================
// 1. Helmet — Security headers (CSP, HSTS, X-Frame-Options, etc.)
//    Applied globally before any route to ensure every response
//    includes protective headers against XSS, clickjacking, etc.
// ============================================================
// Generate a unique nonce per request for inline scripts (CSP)
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.use((req, res, next) => {
  helmetConfig(req, res, next);
});

// ============================================================
// 2. Stripe webhook route — MUST be before express.json()
//    Stripe signature verification requires the raw request body.
//    If JSON parsing runs first, the raw body is consumed and
//    signature verification fails.
// ============================================================
const webhookRoute = require('./routes/webhook');
app.use('/donations/webhook', webhookRoute);

// ============================================================
// 3. Body parsing — JSON and URL-encoded form data
// ============================================================
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(cookieParser());

// ============================================================
// 4. View engine — EJS for server-side HTML rendering
//    Allows embedding CSRF tokens and dynamic data in templates
// ============================================================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ============================================================
// 5. Static files — CSS, client JS, uploaded images
// ============================================================
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));

// ============================================================
// 6. Session configuration
//    - Stored server-side in PostgreSQL via connect-pg-simple
//    - httpOnly: true  → prevents JavaScript access to cookie
//    - secure: true    → cookie sent only over HTTPS (in production)
//    - sameSite: strict → prevents CSRF via cross-origin requests
//    - maxAge: 30 min  → session expires after 30 minutes of idle
//    - Session regeneration happens on login (see routes/auth.js)
// ============================================================
app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: 'session',
    createTableIfMissing: false
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true, // Reset maxAge on every request (idle timeout)
  cookie: {
    httpOnly: true,                                        // Prevents XSS cookie theft
    secure: process.env.NODE_ENV === 'production',         // HTTPS only in production
    sameSite: 'strict',                                    // Blocks cross-site cookie sending
    maxAge: parseInt(process.env.SESSION_DURATION, 10) || 1800000
  }
}));

// ============================================================
// 7. Session-to-User-Agent binding
//    Detects if the User-Agent changes mid-session, which may
//    indicate session hijacking. Destroys the session if mismatch.
// ============================================================
app.use(sessionGuard);

// ============================================================
// 8. Make session user and CSRF token available to all templates
//    This middleware sets res.locals so EJS views can access
//    the current user and flash messages without explicit passing.
// ============================================================
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.success = req.session.success || null;
  res.locals.error = req.session.error || null;
  // Clear flash messages after reading
  delete req.session.success;
  delete req.session.error;
  next();
});

// ============================================================
// 9. CSRF protection — applied globally to all POST/PUT/DELETE
//    Every form must include a hidden _csrf token field.
//    The token is validated server-side on each state-changing request.
//    Protects against cross-site request forgery attacks.
// ============================================================
app.use(csrfProtection);

// Make CSRF token available in all rendered views
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// ============================================================
// 10. Routes
// ============================================================
app.use('/auth', authRoutes);
app.use('/blog', blogRoutes);
app.use('/blog', commentRoutes);
app.use('/donations', donationRoutes);
app.use('/newsletter', newsletterRoutes);
app.use('/settings', settingsRoutes);
app.use('/admin', adminRoutes);

// Home page
app.get('/', async (req, res) => {
  try {
    const { rows: posts } = await pool.query(
      `SELECT p.id, p.title, p.pet_name, p.pet_species, p.image_filename,
              LEFT(p.content, 150) AS excerpt, p.created_at, u.username
       FROM posts p
       JOIN users u ON p.user_id = u.id
       ORDER BY p.created_at DESC
       LIMIT 6`
    );
    res.render('home', { posts });
  } catch (err) {
    console.error('Home page error:', err);
    res.status(500).render('error', { message: 'Something went wrong.' });
  }
});

// ============================================================
// 11. CSRF error handler
//     Returns a 403 if the CSRF token is missing or invalid.
// ============================================================
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).render('error', {
      message: 'Invalid or missing CSRF token. Please refresh the page and try again.'
    });
  }
  next(err);
});

// ============================================================
// 12. Generic error handler
// ============================================================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).render('error', { message: 'Internal server error.' });
});

// ============================================================
// 13. 404 handler
// ============================================================
app.use((req, res) => {
  res.status(404).render('error', { message: 'Page not found.' });
});

// ============================================================
// Start server
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Animal Charity Blog running on http://localhost:${PORT}`);
});

module.exports = app;
