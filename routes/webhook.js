/**
 * Stripe Webhook Route
 * 
 * Handles: Payment confirmation from Stripe
 * 
 * Security:
 * - Verifies the webhook signature using the STRIPE_WEBHOOK_SECRET
 *   to ensure the event genuinely came from Stripe
 * - Uses express.raw() to receive the raw request body needed for
 *   signature verification (this route is registered BEFORE
 *   express.json() in server.js)
 * - Updates donation status only after Stripe confirms payment
 * - All database queries use parameterised syntax
 * 
 * Events handled:
 * - payment_intent.succeeded → marks one-off donation as succeeded
 * - invoice.paid → marks monthly subscription donation as succeeded
 */

const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Raw body parser for Stripe signature verification
router.post('/', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;

  try {
    /**
     * Stripe signature verification:
     * Constructs the event from the raw body and signature header.
     * If the signature is invalid (e.g. the request was tampered with
     * or didn't come from Stripe), this throws an error.
     */
    if (webhookSecret) {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } else {
      // In development without webhook secret, parse the body directly
      event = JSON.parse(req.body.toString());
      console.warn('WARNING: Stripe webhook signature verification is disabled (no STRIPE_WEBHOOK_SECRET).');
    }
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      /**
       * payment_intent.succeeded:
       * Fired when a one-off payment is successfully completed.
       * Updates the corresponding donation record to 'succeeded'.
       */
      case 'payment_intent.succeeded': {
        const paymentIntent = event.data.object;
        await pool.query(
          `UPDATE donations SET status = 'succeeded'
           WHERE stripe_payment_intent_id = $1`,
          [paymentIntent.id]
        );
        console.log(`Payment succeeded: ${paymentIntent.id}`);
        break;
      }

      /**
       * invoice.paid:
       * Fired when a subscription invoice is paid (monthly donation).
       * Updates the donation record for the subscription to 'succeeded'.
       */
      case 'invoice.paid': {
        const invoice = event.data.object;
        if (invoice.subscription) {
          await pool.query(
            `UPDATE donations SET status = 'succeeded'
             WHERE stripe_subscription_id = $1 AND status = 'pending'`,
            [invoice.subscription]
          );
          console.log(`Subscription payment succeeded: ${invoice.subscription}`);
        }
        break;
      }

      /**
       * payment_intent.payment_failed:
       * Fired when a payment attempt fails.
       * Updates the donation status to 'failed'.
       */
      case 'payment_intent.payment_failed': {
        const failedIntent = event.data.object;
        await pool.query(
          `UPDATE donations SET status = 'failed'
           WHERE stripe_payment_intent_id = $1`,
          [failedIntent.id]
        );
        console.log(`Payment failed: ${failedIntent.id}`);
        break;
      }

      default:
        console.log(`Unhandled event type: ${event.type}`);
    }
  } catch (err) {
    console.error('Webhook processing error:', err);
  }

  // Always return 200 to acknowledge receipt
  res.json({ received: true });
});

module.exports = router;
