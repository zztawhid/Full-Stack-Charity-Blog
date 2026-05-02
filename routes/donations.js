/**
 * Donation Routes
 * 
 * Handles: one-off and monthly donations via Stripe
 * 
 * Security mitigations:
 * - Authentication required for all donation actions
 * - Input validation: amount must be positive, max £10,000
 * - Stripe Customer vault: only stripe_customer_id and payment_method_id
 *   are stored, both encrypted with pgp_sym_encrypt
 * - Raw card data is NEVER stored in our database
 * - Parameterised SQL queries throughout
 * - CSRF token required on all forms
 * 
 * Stripe flow:
 * 1. Create or retrieve a Stripe Customer for the user
 * 2. Create a PaymentIntent (one-off) or Subscription (monthly)
 * 3. Frontend uses Stripe.js to collect card details securely
 * 4. Webhook confirms payment success before recording the donation
 */

const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const { requireAuth } = require('../middleware/auth');
const { donationValidation } = require('../middleware/validator');

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const ENCRYPTION_KEY = process.env.DB_ENCRYPTION_KEY;

// ============================================================
// GET /donations — Show donation page
// ============================================================
router.get('/', requireAuth, async (req, res) => {
  try {
    // Fetch user's donation history
    const { rows: donations } = await pool.query(
      `SELECT d.id, d.amount, d.currency, d.type, d.status, d.created_at,
              p.title AS post_title
       FROM donations d
       LEFT JOIN posts p ON d.post_id = p.id
       WHERE d.user_id = $1
       ORDER BY d.created_at DESC`,
      [req.session.user.id]
    );

    // Fetch posts with donation pools enabled
    const { rows: posts } = await pool.query(
      `SELECT id, title, pet_name FROM posts WHERE donation_pool_enabled = TRUE ORDER BY created_at DESC`
    );

    res.render('donations', {
      donations,
      posts,
      stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
      errors: null
    });
  } catch (err) {
    console.error('Donations page error:', err);
    res.status(500).render('error', { message: 'Could not load donations page.' });
  }
});

// ============================================================
// POST /donations/create-payment-intent — Create Stripe PaymentIntent
// 
// Security:
// - Validates donation amount server-side (positive, max £10,000)
// - Creates/retrieves encrypted Stripe Customer ID
// - Never stores raw card data
// ============================================================
router.post('/create-payment-intent', requireAuth, donationValidation, async (req, res) => {
  try {
    if (req.validationErrors) {
      return res.status(400).json({ error: req.validationErrors.join(', ') });
    }

    const { amount, type, post_id } = req.body;
    const amountInPence = Math.round(parseFloat(amount) * 100);

    // Get or create Stripe customer
    const customerId = await getOrCreateStripeCustomer(req.session.user.id);

    if (type === 'monthly') {
      // Create a Stripe Subscription for recurring donations
      // First, create a price for the amount
      const price = await stripe.prices.create({
        unit_amount: amountInPence,
        currency: 'gbp',
        recurring: { interval: 'month' },
        product_data: {
          name: `Monthly Donation - Animal Charity Blog`
        }
      });

      const subscription = await stripe.subscriptions.create({
        customer: customerId,
        items: [{ price: price.id }],
        payment_behavior: 'default_incomplete',
        payment_settings: {
          save_default_payment_method: 'on_subscription'
        },
        expand: ['latest_invoice.payment_intent'],
        metadata: {
          user_id: req.session.user.id.toString(),
          post_id: post_id ? post_id.toString() : '',
          type: 'monthly'
        }
      });

      // Record pending donation
      await pool.query(
        `INSERT INTO donations (user_id, post_id, amount, currency, type, stripe_subscription_id, status)
         VALUES ($1, $2, $3, 'gbp', 'monthly', $4, 'pending')`,
        [req.session.user.id, post_id || null, amountInPence, subscription.id]
      );

      return res.json({
        clientSecret: subscription.latest_invoice.payment_intent.client_secret,
        subscriptionId: subscription.id
      });
    } else {
      // One-off PaymentIntent
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amountInPence,
        currency: 'gbp',
        customer: customerId,
        setup_future_usage: 'off_session', // Save card for future use
        metadata: {
          user_id: req.session.user.id.toString(),
          post_id: post_id ? post_id.toString() : '',
          type: 'one-off'
        }
      });

      // Record pending donation
      await pool.query(
        `INSERT INTO donations (user_id, post_id, amount, currency, type, stripe_payment_intent_id, status)
         VALUES ($1, $2, $3, 'gbp', 'one-off', $4, 'pending')`,
        [req.session.user.id, post_id || null, amountInPence, paymentIntent.id]
      );

      return res.json({
        clientSecret: paymentIntent.client_secret
      });
    }
  } catch (err) {
    console.error('Create payment intent error:', err);
    res.status(500).json({ error: 'Payment processing failed. Please try again.' });
  }
});

// ============================================================
// Helper: Get or create a Stripe Customer for the user
// 
// The Stripe customer ID is encrypted in the database using
// pgp_sym_encrypt. Raw card data is NEVER stored — only the
// customer ID and payment method IDs managed by Stripe.
// ============================================================
async function getOrCreateStripeCustomer(userId) {
  // Try to decrypt existing Stripe customer ID
  const result = await pool.query(
    `SELECT pgp_sym_decrypt(stripe_customer_id, $1) AS stripe_customer_id
     FROM users WHERE id = $2 AND stripe_customer_id IS NOT NULL`,
    [ENCRYPTION_KEY, userId]
  );

  if (result.rows.length > 0 && result.rows[0].stripe_customer_id) {
    return result.rows[0].stripe_customer_id;
  }

  // Get user info for Stripe customer creation
  const userResult = await pool.query(
    `SELECT username, pgp_sym_decrypt(email, $1) AS email FROM users WHERE id = $2`,
    [ENCRYPTION_KEY, userId]
  );

  const user = userResult.rows[0];

  // Create Stripe Customer
  const customer = await stripe.customers.create({
    email: user.email,
    name: user.username,
    metadata: { user_id: userId.toString() }
  });

  // Store encrypted Stripe customer ID (parameterised query)
  await pool.query(
    'UPDATE users SET stripe_customer_id = pgp_sym_encrypt($1, $2) WHERE id = $3',
    [customer.id, ENCRYPTION_KEY, userId]
  );

  return customer.id;
}

module.exports = router;
