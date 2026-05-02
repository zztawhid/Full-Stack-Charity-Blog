/**
 * Authentication Middleware
 * 
 * Protects against: Unauthorised access to protected resources
 * 
 * How it works:
 * - requireAuth: checks that a valid session with a user exists.
 *   If not, redirects to the login page. Used on all routes that
 *   require a logged-in user (blog creation, settings, donations, etc.)
 * 
 * - requireGuest: ensures the user is NOT logged in. Used on login
 *   and register pages to prevent authenticated users from seeing them.
 */

/**
 * Requires the user to be authenticated (logged in with MFA verified).
 * Redirects to /auth/login if no valid session user is found.
 */
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    req.session.error = 'Please log in to access this page.';
    return res.redirect('/auth/login');
  }
  next();
}

/**
 * Requires the user to NOT be authenticated.
 * Redirects to home page if the user is already logged in.
 */
function requireGuest(req, res, next) {
  if (req.session && req.session.user) {
    return res.redirect('/');
  }
  next();
}

module.exports = { requireAuth, requireGuest };
