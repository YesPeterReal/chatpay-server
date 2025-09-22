const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const stripe = require('stripe');
const cors = require('cors');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

const pool = new Pool({
    host: 'chatpay-postgres-new.cxwak020irdl.eu-west-3.rds.amazonaws.com',
    port: 5432,
    user: 'chatpay',
    password: process.env.POSTGRES_PASSWORD || 'default-postgres-password',
    database: 'postgres',
    ssl: {
        rejectUnauthorized: false,
        ca: process.env.NODE_ENV === 'production' 
            ? fs.readFileSync('/app/rds-ca-bundle.pem').toString()
            : undefined,
    },
});

const secretsmanager = new SecretsManagerClient({ region: 'eu-west-3' });

async function getSecret(secretName) {
    try {
        const command = new GetSecretValueCommand({ SecretId: secretName });
        const data = await secretsmanager.send(command);
        return JSON.parse(data.SecretString);
    } catch (error) {
        console.error(`Error retrieving secret ${secretName}:`, error.message);
        return null;
    }
}

let transporter = null;
let stripeClient = null;

async function initializeSecrets() {
    try {
        const sesCredentials = await getSecret('chatpay/ses-credentials');
        if (sesCredentials && sesCredentials.SMTP_USERNAME && sesCredentials.SMTP_PASSWORD) {
            process.env.SMTP_USERNAME = sesCredentials.SMTP_USERNAME;
            process.env.SMTP_PASSWORD = sesCredentials.SMTP_PASSWORD;
            transporter = nodemailer.createTransport({
                host: 'email-smtp.eu-west-3.amazonaws.com',
                port: 587,
                auth: {
                    user: process.env.SMTP_USERNAME,
                    pass: process.env.SMTP_PASSWORD,
                },
            });
        } else {
            console.warn('SES credentials not found or incomplete; email functionality disabled');
        }

        const jwtSecret = await getSecret('chatpay/jwt-secret');
        process.env.JWT_SECRET = jwtSecret?.JWT_SECRET || 'default-jwt-secret';

        const stripeSecret = await getSecret('chatpay/stripe-secret-key');
        if (stripeSecret && stripeSecret.STRIPE_SECRET_KEY) {
            process.env.STRIPE_SECRET_KEY = stripeSecret.STRIPE_SECRET_KEY;
            stripeClient = stripe(process.env.STRIPE_SECRET_KEY);
            console.log('Stripe client initialized successfully');
        } else {
            console.warn('Stripe secret key not found or incomplete; payment functionality disabled');
        }

        return true;
    } catch (error) {
        console.error('Failed to initialize secrets:', error.message);
        return false;
    }
}

initializeSecrets().then(success => {
    if (!success) {
        console.warn('Running with limited functionality due to secrets initialization failure');
    }
});

app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'healthy' });
    } catch (error) {
        console.error('Health check failed:', error.message);
        res.status(500).json({ status: 'unhealthy', error: error.message });
    }
});

app.post('/signup', async (req, res) => {
    const { email, password, name, surname } = req.body;
    if (!email || !password || !name || !surname) {
        return res.status(400).json({ error: 'Name, Surname, Email, and Password are required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = uuidv4();
        await pool.query(
            'INSERT INTO users (id, email, password, name, surname) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (email) DO NOTHING',
            [userId, email, hashedPassword, name, surname]
        );
        const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        const token = jwt.sign({ user_id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error('Signup failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/signin', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    try {
        const result = await pool.query('SELECT id, password FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const { id, password: hashedPassword } = result.rows[0];
        const isValid = await bcrypt.compare(password, hashedPassword);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ user_id: id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error('Signin failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    console.log('Received forgot-password request for:', email);
    if (!email) {
        console.log('Missing email in request');
        return res.status(400).json({ error: 'Email is required' });
    }
    if (!transporter) {
        console.log('Transporter not initialized');
        return res.status(503).json({ error: 'Email service is not available' });
    }
    try {
        const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            console.log('User not found for email:', email);
            return res.status(404).json({ error: 'User not found' });
        }
        const userId = result.rows[0].id;
        const resetToken = uuidv4();
        const expiry = new Date(Date.now() + 3600000); // 1 hour expiry
        await pool.query(
            'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE id = $3',
            [resetToken, expiry, userId]
        );
        console.log('Generated reset token:', resetToken);
        const mailResult = await transporter.sendMail({
            from: 'dpeterojo@gmail.com',
            to: email,
            subject: 'ChatPay Password Reset',
            text: `To reset your password, use this token: ${resetToken}\n\nThis token expires in 1 hour.`,
            html: `<p>To reset your password, use this token: <strong>${resetToken}</strong></p><p>This token expires in 1 hour.</p>`,
        });
        console.log('Email sent successfully:', mailResult);
        res.json({ message: 'Password reset email sent' });
    } catch (error) {
        console.error('Forgot password failed:', error.message, error);
        res.status(500).json({ error: `Message failed: ${error.message}` });
    }
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Token and new password are required' });
    }
    try {
        const result = await pool.query(
            'SELECT id FROM users WHERE reset_token = $1 AND reset_token_expiry > $2',
            [token, new Date()]
        );
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }
        const userId = result.rows[0].id;
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query(
            'UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2',
            [hashedPassword, userId]
        );
        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Reset password failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/wallet/balance', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const rows = await pool.query('SELECT balance, currency FROM wallets WHERE user_id = $1 AND status = $2', [decoded.user_id, 'active']);
        res.json(rows.rows);
    } catch (error) {
        console.error('Wallet balance failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/payments/received', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const rows = await pool.query(
            'SELECT payment_intent_id, amount, currency, status, created_at FROM payments WHERE receiver_id = $1 AND status = $2',
            [decoded.user_id, 'succeeded']
        );
        res.json(rows.rows);
    } catch (error) {
        console.error('Payments received failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/list-payments', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const rows = await pool.query(
            'SELECT payment_intent_id, amount, currency, status, created_at FROM payments WHERE sender_id = $1 OR receiver_id = $1',
            [decoded.user_id]
        );
        res.json(rows.rows);
    } catch (error) {
        console.error('List payments failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/create-payment', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const { amount, currency, sender_id, receiver_id } = req.body;
    if (!amount || !currency || !sender_id || !receiver_id) {
        return res.status(400).json({ error: 'Amount, currency, sender_id, and receiver_id are required' });
    }
    if (!stripeClient) return res.status(503).json({ error: 'Stripe service is not available' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        // Validate sender_id and receiver_id exist
        const senderCheck = await pool.query('SELECT id FROM users WHERE id = $1', [sender_id]);
        if (senderCheck.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid sender_id' });
        }
        const receiverCheck = await pool.query('SELECT id FROM users WHERE id = $1', [receiver_id]);
        if (receiverCheck.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid receiver_id' });
        }
        const pi = await stripeClient.paymentIntents.create({ amount, currency, payment_method_types: ['card'] });
        const exists = await pool.query('SELECT EXISTS(SELECT 1 FROM payments WHERE payment_intent_id = $1)', [pi.id]);
        if (!exists.rows[0].exists) {
            await pool.query(
                'INSERT INTO payments (payment_intent_id, sender_id, receiver_id, amount, currency, status, method) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                [pi.id, sender_id, receiver_id, amount / 100, currency, pi.status, 'card']
            );
        }
        res.json({ paymentIntentId: pi.id, amount: amount / 100, currency, status: pi.status, createdAt: new Date().toISOString() });
    } catch (error) {
        console.error('Create payment failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/request-payment', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const { amount, currency, requester_id, target_id } = req.body;
    if (!amount || !currency || !requester_id || !target_id) {
        return res.status(400).json({ error: 'Amount, currency, requester_id, and target_id are required' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        // Validate requester_id and target_id exist
        const requesterCheck = await pool.query('SELECT id FROM users WHERE id = $1', [requester_id]);
        if (requesterCheck.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid requester_id' });
        }
        const targetCheck = await pool.query('SELECT id FROM users WHERE id = $1', [target_id]);
        if (targetCheck.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid target_id' });
        }
        await pool.query(
            'INSERT INTO payment_requests (id, requester_id, target_id, amount, currency, status) VALUES ($1, $2, $3, $4, $5, $6)',
            [uuidv4(), requester_id, target_id, amount / 100, currency, 'pending']
        );
        res.json({ status: 'request_created' });
    } catch (error) {
        console.error('Request payment failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.listen(3000, () => console.log('Server running on port 3000'));