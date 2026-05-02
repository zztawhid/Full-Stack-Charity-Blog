/**
 * Session Guard Middleware
 * 
 * Protects against: Session hijacking
 * 
 * How it works:
 * - On first request, stores the User-Agent string in the session
 * - On subsequent requests, compares the current User-Agent to the stored one
 * - If they don't match, the session is destroyed immediately
 * 
 * Why: If an attacker steals a session cookie and replays it from a different
 * browser or tool, the User-Agent will differ. This is a secondary defence
 * layer — not foolproof (User-Agent can be spoofed) but raises the bar.
 */

/**
 * Binds the session to the User-Agent that created it.
 * Destroys the session on User-Agent mismatch.
 */
function sessionGuard(req, res, next) {
  if (!req.session) {
    return next();
  }

  const currentUA = req.headers['user-agent'] || '';

  // First request — store the User-Agent
  if (!req.session._ua) {
    req.session._ua = currentUA;
    return next();
  }

  // Subsequent requests — verify the User-Agent matches
  if (req.session._ua !== currentUA) {
    console.warn(`Session guard: User-Agent mismatch for session ${req.sessionID}. Possible hijacking attempt.`);
    return req.session.destroy((err) => {
      if (err) console.error('Session destroy error:', err);
      return res.status(403).render('error', {
        message: 'Session invalidated due to a security check. Please log in again.'
      });
    });
  }

  next();
}

module.exports = { sessionGuard };
