/**
 * CSRF Protection Middleware
 * 
 * Protects against: Cross-Site Request Forgery (CSRF)
 * 
 * CSRF attacks trick authenticated users into submitting malicious requests
 * (e.g. changing their password or making a donation) from an attacker's site.
 * 
 * How it works:
 * - csurf generates a unique token per session
 * - The token is embedded as a hidden field in every HTML form
 * - On form submission (POST/PUT/DELETE), csurf validates the token
 * - If the token is missing or wrong, the request is rejected with 403
 * 
 * The token is stored in the session (not a cookie) for extra safety.
 */

const csurf = require('csurf');

// Use session-based CSRF token storage (requires express-session)
module.exports = csurf({ cookie: false });
