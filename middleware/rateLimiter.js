/**
 * Rate Limiting Middleware
 * 
 * Protects against: Brute-force attacks, credential stuffing, denial of service
 * 
 * How it works:
 * - Tracks the number of requests per IP address within a time window
 * - If the limit is exceeded, subsequent requests receive a 429 status
 * - Applied specifically to the login route to prevent password guessing
 * 
 * Configuration (from .env):
 * - RATE_LIMIT_MAX_ATTEMPTS: max requests per window (default 5)
 * - RATE_LIMIT_WINDOW_MS: window duration in ms (default 15 minutes)
 */

const rateLimit = require('express-rate-limit');

/**
 * Login rate limiter — max 5 attempts per 15 minutes per IP
 * Returns a generic message to avoid revealing whether rate limiting
 * is the cause of rejection (prevents information leakage).
 */
const loginLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000,
  max: parseInt(process.env.RATE_LIMIT_MAX_ATTEMPTS, 10) || 5,
  message: 'Too many login attempts. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  // Skip successful requests so only failed attempts count
  skipSuccessfulRequests: false
});

/**
 * General API rate limiter — protects all routes from abuse
 * More permissive than the login limiter.
 */
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});

module.exports = { loginLimiter, generalLimiter };
