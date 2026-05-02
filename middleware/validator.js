/**
 * Input Validation Middleware
 * 
 * Protects against: SQL injection, XSS, invalid data, business logic abuse
 * 
 * How it works:
 * - Uses express-validator to define validation chains for each form
 * - Each chain specifies field-level rules (type, length, format, etc.)
 * - The handleValidation middleware checks for errors and re-renders
 *   the form with error messages if validation fails
 * - Uses the xss npm package to sanitise text inputs server-side,
 *   stripping any HTML/script tags before storage
 * 
 * Password strength: min 8 chars, 1 uppercase, 1 number, 1 symbol
 * Donation amount: positive number, max £10,000
 */

const { body, validationResult } = require('express-validator');
const xss = require('xss');

/**
 * XSS sanitisation helper — strips all HTML tags and script content
 * from user input before it is stored in the database.
 * Applied to all text fields (titles, content, comments, etc.)
 */
function sanitise(value) {
  if (typeof value !== 'string') return value;
  return xss(value.trim());
}

/**
 * Checks validation results from express-validator.
 * If errors exist, returns them in a format routes can use.
 */
function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Store errors in session for display, then the route handles redirect
    req.validationErrors = errors.array().map(e => e.msg);
    return next();
  }
  req.validationErrors = null;
  next();
}

// ============================================================
// Validation chains for each form
// ============================================================

/**
 * Registration form validation
 * - Username: 3–50 alphanumeric characters
 * - Email: valid email format
 * - Password: min 8 chars, 1 uppercase, 1 number, 1 symbol
 */
const registerValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 }).withMessage('Username must be 3–50 characters.')
    .isAlphanumeric().withMessage('Username must contain only letters and numbers.')
    .customSanitizer(sanitise),
  body('email')
    .trim()
    .isEmail().withMessage('Please enter a valid email address.')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters.')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter.')
    .matches(/[0-9]/).withMessage('Password must contain at least one number.')
    .matches(/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/~`]/).withMessage('Password must contain at least one symbol.'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match.');
      }
      return true;
    }),
  handleValidation
];

/**
 * Login form validation — basic presence checks only
 * Detailed error messages are NOT returned to prevent account enumeration
 */
const loginValidation = [
  body('username').trim().notEmpty().withMessage('Username is required.'),
  body('password').notEmpty().withMessage('Password is required.'),
  handleValidation
];

/**
 * Blog post validation
 * - Title: 1–200 characters, sanitised for XSS
 * - Content: non-empty, sanitised for XSS
 * - Pet name and species: optional, sanitised
 */
const postValidation = [
  body('title')
    .trim()
    .isLength({ min: 1, max: 200 }).withMessage('Title is required (max 200 characters).')
    .customSanitizer(sanitise),
  body('content')
    .trim()
    .notEmpty().withMessage('Post content is required.')
    .customSanitizer(sanitise),
  body('pet_name')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 }).withMessage('Pet name max 100 characters.')
    .customSanitizer(sanitise),
  body('pet_species')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 50 }).withMessage('Species max 50 characters.')
    .customSanitizer(sanitise),
  handleValidation
];

/**
 * Comment validation — sanitised to prevent stored XSS
 */
const commentValidation = [
  body('content')
    .trim()
    .notEmpty().withMessage('Comment cannot be empty.')
    .isLength({ max: 2000 }).withMessage('Comment max 2000 characters.')
    .customSanitizer(sanitise),
  handleValidation
];

/**
 * Donation amount validation
 * - Must be a positive number
 * - Maximum £10,000 (1000000 pence)
 */
const donationValidation = [
  body('amount')
    .isFloat({ min: 0.50, max: 10000 }).withMessage('Donation must be between £0.50 and £10,000.'),
  body('type')
    .isIn(['one-off', 'monthly']).withMessage('Donation type must be one-off or monthly.'),
  handleValidation
];

/**
 * Password change validation — includes strength check
 */
const passwordChangeValidation = [
  body('currentPassword')
    .notEmpty().withMessage('Current password is required.'),
  body('newPassword')
    .isLength({ min: 8 }).withMessage('New password must be at least 8 characters.')
    .matches(/[A-Z]/).withMessage('New password must contain at least one uppercase letter.')
    .matches(/[0-9]/).withMessage('New password must contain at least one number.')
    .matches(/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/~`]/).withMessage('New password must contain at least one symbol.'),
  body('confirmNewPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('New passwords do not match.');
      }
      return true;
    }),
  handleValidation
];

/**
 * Email change validation
 */
const emailChangeValidation = [
  body('currentPassword')
    .notEmpty().withMessage('Current password is required for re-authentication.'),
  body('newEmail')
    .trim()
    .isEmail().withMessage('Please enter a valid email address.')
    .normalizeEmail(),
  handleValidation
];

/**
 * Newsletter post validation (admin)
 */
const newsletterValidation = [
  body('title')
    .trim()
    .isLength({ min: 1, max: 200 }).withMessage('Title is required (max 200 chars).')
    .customSanitizer(sanitise),
  body('content')
    .trim()
    .notEmpty().withMessage('Newsletter content is required.')
    .customSanitizer(sanitise),
  handleValidation
];

/**
 * Forgot password email validation
 */
const forgotPasswordValidation = [
  body('email')
    .trim()
    .isEmail().withMessage('Please enter a valid email address.')
    .normalizeEmail(),
  handleValidation
];

/**
 * Reset password validation
 */
const resetPasswordValidation = [
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters.')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter.')
    .matches(/[0-9]/).withMessage('Password must contain at least one number.')
    .matches(/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/~`]/).withMessage('Password must contain at least one symbol.'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match.');
      }
      return true;
    }),
  handleValidation
];

module.exports = {
  sanitise,
  handleValidation,
  registerValidation,
  loginValidation,
  postValidation,
  commentValidation,
  donationValidation,
  passwordChangeValidation,
  emailChangeValidation,
  newsletterValidation,
  forgotPasswordValidation,
  resetPasswordValidation
};
