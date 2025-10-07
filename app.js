const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors({
    origin: [
        'http://localhost:3000',
        'https://chatpay-frontend.vercel.app',
        'https://chatpay-frontend.onrender.com'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}));

const pool = new Pool({
    host: process.env.POSTGRES_HOST,
    port: process.env.POSTGRES_PORT || 5432,
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
    database: process.env.POSTGRES_DB,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const JWT_SECRET = process.env.JWT_SECRET || 'default-jwt-secret';

// Mock Stripe if no key
const stripeClient = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : {
    paymentIntents: { create: () => ({ id: uuidv4() }) },
    payouts: { create: () => ({ id: uuidv4() }) }
};

const convertAmount = (amount, fromCurrency, toCurrency) => {
    if (fromCurrency === toCurrency) return amount;
    const rates = {
        USD: { NGN: 1600, EUR: 0.85, CNY: 7.1 },
        NGN: { USD: 1/1600, EUR: 0.00053125, CNY: 0.0044375 },
        EUR: { USD: 1.176, NGN: 1882.35, CNY: 8.35 },
        CNY: { USD: 0.1408, NGN: 225.35, EUR: 0.1198 },
    };
    return Math.round(amount * rates[fromCurrency][toCurrency] * 100) / 100;
};

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
    const { email, password, name, surname, gender, phone, dob } = req.body;
    if (!email || !password || !name || !surname) {
        return res.status(400).json({ error: 'Name, Surname, Email, and Password are required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = uuidv4();
        await pool.query(
            'INSERT INTO users (id, email, password, name, surname, gender, phone, dob) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (email) DO NOTHING',
            [userId, email, hashedPassword, name, surname, gender || null, phone || null, dob || null]
        );
        const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        const token = jwt.sign({ user_id: userId }, JWT_SECRET, { expiresIn: '1h' });
        const currencies = ['USD', 'NGN', 'EUR', 'CNY'];
        for (const currency of currencies) {
            await pool.query(
                'INSERT INTO wallets (id, user_id, balance, currency, status, created_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (user_id, currency) DO NOTHING',
                [uuidv4(), userId, 0, currency, 'active', new Date()]
            );
        }
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
        const token = jwt.sign({ user_id: id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error('Signin failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/forgot-password', async (req, res) => {
    // Disabled due to no SES; implement later if needed
    res.status(503).json({ error: 'Email service is not available' });
});

app.post('/reset-password', async (req, res) => {
    // Disabled due to no SES; implement later if needed
    res.status(503).json({ error: 'Email service is not available' });
});

app.get('/wallet/balance', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const rows = await pool.query('SELECT balance, currency FROM wallets WHERE user_id = $1 AND status = $2', [decoded.user_id, 'active']);
        res.json(rows.rows);
    } catch (error) {
        console.error('Wallet balance failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/recent-transactions', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const rows = await pool.query(
            `SELECT payment_intent_id AS id, amount, currency, method AS type, created_at
             FROM payments
             WHERE sender_id = $1 OR receiver_id = $1
             ORDER BY created_at DESC
             LIMIT 5`,
            [decoded.user_id]
        );
        res.json(rows.rows);
    } catch (error) {
        console.error('Recent transactions failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/payments/received', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
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
        const decoded = jwt.verify(token, JWT_SECRET);
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

app.post('/user-by-email', async (req, res) => {
    const { email } = req.body;
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    if (!email) return res.status(400).json({ error: 'Email is required' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ user_id: result.rows[0].id });
    } catch (error) {
        console.error('User lookup failed:', error.message);
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
    if (!['USD', 'NGN', 'EUR', 'CNY'].includes(currency)) {
        return res.status(400).json({ error: 'Invalid currency. Must be USD, NGN, EUR, or CNY' });
    }
    if (amount < 1 || amount > 500) {
        return res.status(400).json({ error: `Amount must be between 1 and 500 ${currency}` });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.user_id !== sender_id) {
            return res.status(403).json({ error: 'Unauthorized sender' });
        }
        const senderWallet = await pool.query(
            'SELECT balance FROM wallets WHERE user_id = $1 AND currency = $2 AND status = $3',
            [sender_id, currency, 'active']
        );
        if (senderWallet.rows.length === 0) {
            return res.status(404).json({ error: 'Sender wallet not found' });
        }
        if (senderWallet.rows[0].balance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        const receiverWallet = await pool.query(
            'SELECT id FROM wallets WHERE user_id = $1 AND currency = $2 AND status = $3',
            [receiver_id, currency, 'active']
        );
        if (receiverWallet.rows.length === 0) {
            return res.status(404).json({ error: 'Receiver wallet not found' });
        }
        let paymentIntentId = uuidv4();
        if (stripeClient.paymentIntents && process.env.STRIPE_SECRET_KEY) {
            const amountInUsd = currency === 'USD' ? amount : convertAmount(amount, currency, 'USD');
            const amountInCents = Math.round(amountInUsd * 100);
            const paymentIntent = await stripeClient.paymentIntents.create({
                amount: amountInCents,
                currency: 'usd',
                payment_method_types: ['card'],
                metadata: { sender_id, receiver_id, original_currency: currency, original_amount: amount },
            });
            paymentIntentId = paymentIntent.id;
        }
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(
                'UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND currency = $3',
                [amount, sender_id, currency]
            );
            await client.query(
                'UPDATE wallets SET balance = balance + $1 WHERE user_id = $2 AND currency = $3',
                [amount, receiver_id, currency]
            );
            await client.query(
                'INSERT INTO payments (payment_intent_id, amount, currency, sender_id, receiver_id, status, method, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
                [paymentIntentId, amount, currency, sender_id, receiver_id, 'succeeded', 'card', new Date()]
            );
            await client.query('COMMIT');
            res.json({ message: 'Payment created successfully', paymentIntentId });
        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Create payment failed:', error.message);
            res.status(500).json({ error: error.message });
        } finally {
            client.release();
        }
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
    if (!['USD', 'NGN', 'EUR', 'CNY'].includes(currency)) {
        return res.status(400).json({ error: 'Invalid currency. Must be USD, NGN, EUR, or CNY' });
    }
    if (amount < 1 || amount > 500) {
        return res.status(400).json({ error: `Amount must be between 1 and 500 ${currency}` });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.user_id !== requester_id) {
            return res.status(403).json({ error: 'Unauthorized requester' });
        }
        const requesterWallet = await pool.query(
            'SELECT id FROM wallets WHERE user_id = $1 AND currency = $2 AND status = $3',
            [requester_id, currency, 'active']
        );
        if (requesterWallet.rows.length === 0) {
            return res.status(404).json({ error: 'Requester wallet not found' });
        }
        const targetWallet = await pool.query(
            'SELECT id FROM wallets WHERE user_id = $1 AND currency = $2 AND status = $3',
            [target_id, currency, 'active']
        );
        if (targetWallet.rows.length === 0) {
            return res.status(404).json({ error: 'Target wallet not found' });
        }
        let paymentIntentId = uuidv4();
        if (stripeClient.paymentIntents && process.env.STRIPE_SECRET_KEY) {
            const amountInUsd = currency === 'USD' ? amount : convertAmount(amount, currency, 'USD');
            const amountInCents = Math.round(amountInUsd * 100);
            const paymentIntent = await stripeClient.paymentIntents.create({
                amount: amountInCents,
                currency: 'usd',
                payment_method_types: ['card'],
                metadata: { requester_id, target_id, original_currency: currency, original_amount: amount },
            });
            paymentIntentId = paymentIntent.id;
        }
        await pool.query(
            'INSERT INTO payment_requests (id, requester_id, target_id, amount, currency, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [uuidv4(), requester_id, target_id, amount, currency, 'pending', new Date()]
        );
        res.json({ message: 'Payment request created successfully', paymentIntentId });
    } catch (error) {
        console.error('Request payment failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/fund-wallet', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const { amount, currency, payment_method, user_id } = req.body;
    if (!amount || !currency || !payment_method || !user_id) {
        return res.status(400).json({ error: 'Amount, currency, payment_method, and user_id are required' });
    }
    if (!['USD', 'NGN', 'EUR', 'CNY'].includes(currency)) {
        return res.status(400).json({ error: 'Invalid currency. Must be USD, NGN, EUR, or CNY' });
    }
    if (amount < 1 || amount > 500) {
        return res.status(400).json({ error: `Amount must be between 1 and 500 ${currency}` });
    }
    if (!['card', 'crypto'].includes(payment_method)) {
        return res.status(400).json({ error: 'Invalid payment method' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.user_id !== user_id) {
            return res.status(403).json({ error: 'Unauthorized user' });
        }
        const wallet = await pool.query(
            'SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = $2 AND status = $3',
            [user_id, currency, 'active']
        );
        if (wallet.rows.length === 0) {
            return res.status(404).json({ error: 'Wallet not found' });
        }
        let paymentIntentId = uuidv4();
        if (stripeClient.paymentIntents && process.env.STRIPE_SECRET_KEY && payment_method === 'card') {
            const amountInUsd = currency === 'USD' ? amount : convertAmount(amount, currency, 'USD');
            const amountInCents = Math.round(amountInUsd * 100);
            const paymentIntent = await stripeClient.paymentIntents.create({
                amount: amountInCents,
                currency: 'usd',
                payment_method_types: ['card'],
                metadata: { user_id, original_currency: currency, original_amount: amount },
            });
            paymentIntentId = paymentIntent.id;
        }
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(
                'UPDATE wallets SET balance = balance + $1 WHERE user_id = $2 AND currency = $3',
                [amount, user_id, currency]
            );
            await client.query(
                'INSERT INTO payments (payment_intent_id, amount, currency, sender_id, receiver_id, status, method, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
                [paymentIntentId, amount, currency, user_id, user_id, 'succeeded', payment_method, new Date()]
            );
            await client.query('COMMIT');
            res.json({ message: 'Wallet funded successfully', paymentIntentId });
        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Fund wallet failed:', error.message);
            res.status(500).json({ error: error.message });
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Fund wallet failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/withdraw-wallet', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const { amount, currency, payment_method, user_id } = req.body;
    if (!amount || !currency || !payment_method || !user_id) {
        return res.status(400).json({ error: 'Amount, currency, payment_method, and user_id are required' });
    }
    if (!['USD', 'NGN', 'EUR', 'CNY'].includes(currency)) {
        return res.status(400).json({ error: 'Invalid currency. Must be USD, NGN, EUR, or CNY' });
    }
    if (amount < 1 || amount > 500) {
        return res.status(400).json({ error: `Amount must be between 1 and 500 ${currency}` });
    }
    if (!['card', 'crypto'].includes(payment_method)) {
        return res.status(400).json({ error: 'Invalid payment method' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.user_id !== user_id) {
            return res.status(403).json({ error: 'Unauthorized user' });
        }
        const wallet = await pool.query(
            'SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = $2 AND status = $3',
            [user_id, currency, 'active']
        );
        if (wallet.rows.length === 0) {
            return res.status(404).json({ error: 'Wallet not found' });
        }
        if (wallet.rows[0].balance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        let payoutId = uuidv4();
        if (stripeClient.payouts && process.env.STRIPE_SECRET_KEY && payment_method === 'card') {
            const amountInUsd = currency === 'USD' ? amount : convertAmount(amount, currency, 'USD');
            const amountInCents = Math.round(amountInUsd * 100);
            const payout = await stripeClient.payouts.create({
                amount: amountInCents,
                currency: 'usd',
                method: 'standard',
                metadata: { user_id, original_currency: currency, original_amount: amount },
            });
            payoutId = payout.id;
        }
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(
                'UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND currency = $3',
                [amount, user_id, currency]
            );
            await client.query(
                'INSERT INTO payments (payment_intent_id, amount, currency, sender_id, receiver_id, status, method, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
                [payoutId, amount, currency, user_id, user_id, 'succeeded', payment_method, new Date()]
            );
            await client.query('COMMIT');
            res.json({ message: 'Withdrawal requested successfully', paymentIntentId: payoutId });
        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Withdraw wallet failed:', error.message);
            res.status(500).json({ error: error.message });
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Withdraw wallet failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/user/preferences', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const result = await pool.query('SELECT name, email FROM users WHERE id = $1', [decoded.user_id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Fetch preferences failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/user/preferences', async (req, res) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const { name, email } = req.body;
    if (!name || !email) {
        return res.status(400).json({ error: 'Name and email are required' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        await pool.query('UPDATE users SET name = $1, email = $2 WHERE id = $3', [name, email, decoded.user_id]);
        res.json({ message: 'Preferences updated successfully' });
    } catch (error) {
        console.error('Update preferences failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));