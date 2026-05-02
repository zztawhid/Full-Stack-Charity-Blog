/**
 * Helmet Security Headers Middleware
 * 
 * Protects against: XSS, clickjacking, MIME-type sniffing, and other
 * client-side attacks by setting a comprehensive suite of HTTP headers.
 * 
 * Headers set:
 * - Content-Security-Policy: restricts sources of scripts, styles, images
 *   to prevent inline script injection (XSS)
 * - Strict-Transport-Security (HSTS): forces HTTPS for 1 year
 * - X-Frame-Options: DENY — prevents embedding in iframes (clickjacking)
 * - X-Content-Type-Options: nosniff — prevents MIME-type confusion
 * - Referrer-Policy: same-origin — limits referrer leakage
 * - X-Permitted-Cross-Domain-Policies: none
 */

const helmet = require('helmet');

module.exports = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://js.stripe.com", (req, res) => `'nonce-${res.locals.cspNonce}'`],
      styleSrc: ["'self'", "'unsafe-inline'"],    // unsafe-inline needed for basic styling
      imgSrc: ["'self'", "data:", "https://*.stripe.com"],
      connectSrc: ["'self'", "https://api.stripe.com", "https://m.stripe.network", "https://m.stripe.com"],
      frameSrc: ["'self'", "https://js.stripe.com", "https://m.stripe.network"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  // HSTS: force HTTPS for 1 year, include subdomains
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true
  },
  // Prevent page from being loaded in an iframe
  frameguard: { action: 'deny' },
  // Prevent MIME-type sniffing
  noSniff: true,
  // Control referrer information
  referrerPolicy: { policy: 'same-origin' },
  // Disable cross-domain embedding
  permittedCrossDomainPolicies: { permittedPolicies: 'none' }
});
