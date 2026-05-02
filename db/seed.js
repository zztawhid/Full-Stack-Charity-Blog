/**
 * Database Seed Script
 * 
 * Creates the initial admin account using credentials from .env.
 * The admin password is hashed with bcrypt (salt rounds 12) after
 * appending the server-side pepper.
 * Email is encrypted with pgp_sym_encrypt using the DB_ENCRYPTION_KEY.
 * TOTP secret is generated and encrypted for the admin user.
 * 
 * Usage: node db/seed.js
 */

require('dotenv').config();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const pool = require('./pool');

const SALT_ROUNDS = 12;

async function seed() {
  const client = await pool.connect();

  try {
    const { rows } = await client.query(
      'SELECT id FROM users WHERE username = $1',
      [process.env.ADMIN_USERNAME]
    );

    if (rows.length > 0) {
      console.log('Admin account already exists. Skipping seed.');
      return;
    }

    // Hash password with pepper appended
    const peppered = process.env.ADMIN_PASSWORD + process.env.PEPPER;
    const passwordHash = await bcrypt.hash(peppered, SALT_ROUNDS);

    // Generate TOTP secret for admin
    const totpSecret = speakeasy.generateSecret({
      name: `${process.env.TOTP_APP_NAME}:${process.env.ADMIN_USERNAME}`,
      issuer: process.env.TOTP_APP_NAME
    });

    // Create SHA-256 hash of email for lookups
    const emailHash = crypto
      .createHash('sha256')
      .update(process.env.ADMIN_EMAIL.toLowerCase().trim())
      .digest('hex');

    const encryptionKey = process.env.DB_ENCRYPTION_KEY;

    // Insert admin user with encrypted email and TOTP secret
    await client.query(
      `INSERT INTO users (username, email, email_hash, password_hash, totp_secret, totp_verified, role, newsletter_opted_in)
       VALUES ($1, pgp_sym_encrypt($2, $3), $4, $5, pgp_sym_encrypt($6, $3), TRUE, 'admin', FALSE)`,
      [
        process.env.ADMIN_USERNAME,
        process.env.ADMIN_EMAIL,
        encryptionKey,
        emailHash,
        passwordHash,
        totpSecret.base32
      ]
    );

    console.log('=== Admin account seeded successfully ===');
    console.log(`Username: ${process.env.ADMIN_USERNAME}`);
    console.log(`TOTP Secret (base32): ${totpSecret.base32}`);
    console.log('Add this secret to your authenticator app (e.g. Google Authenticator).');
    console.log(`Or use this otpauth URL: ${totpSecret.otpauth_url}`);
  } catch (err) {
    console.error('Seed error:', err);
  } finally {
    client.release();
    await pool.end();
  }
}

seed();
