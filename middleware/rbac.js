/**
 * Role-Based Access Control (RBAC) Middleware
 * 
 * Protects against: Privilege escalation, unauthorised admin access
 * 
 * How it works:
 * - Checks the authenticated user's role stored in the session
 * - If the user's role does not match the required role, returns 403
 * - Applied to all admin routes to ensure only admins can access them
 * 
 * Roles: 'user' (default), 'admin'
 */

/**
 * Returns middleware that checks whether the logged-in user has the
 * specified role. Must be used AFTER requireAuth middleware.
 * 
 * @param {string} role - Required role (e.g. 'admin')
 */
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session || !req.session.user) {
      return res.status(401).render('error', { message: 'Authentication required.' });
    }

    if (req.session.user.role !== role) {
      return res.status(403).render('error', {
        message: 'Access denied. You do not have permission to view this page.'
      });
    }

    next();
  };
}

module.exports = { requireRole };
