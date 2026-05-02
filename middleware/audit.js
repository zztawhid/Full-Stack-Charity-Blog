/**
 * Audit Logging Middleware
 * 
 * Protects against: Undetected admin abuse, lack of accountability
 * 
 * How it works:
 * - Provides a helper function that writes a record to the audit_log table
 * - Every admin action (user management, post deletion, etc.) calls this
 *   function with the action details
 * - Records: who did what, to which resource, from which IP, and when
 * - Uses parameterised queries to prevent SQL injection in log entries
 */

const pool = require('../db/pool');

/**
 * Writes an entry to the audit_log table.
 * 
 * @param {number} userId     - ID of the user performing the action
 * @param {string} action     - Description of the action (e.g. 'delete_user')
 * @param {string} targetType - Type of resource affected (e.g. 'user', 'post')
 * @param {number} targetId   - ID of the affected resource
 * @param {string} ipAddress  - IP address of the request
 */
async function logAudit(userId, action, targetType, targetId, ipAddress) {
  try {
    await pool.query(
      `INSERT INTO audit_log (user_id, action, target_type, target_id, ip_address)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, action, targetType, targetId, ipAddress]
    );
  } catch (err) {
    // Log to console but don't crash the request if audit logging fails
    console.error('Audit log write error:', err);
  }
}

module.exports = { logAudit };
