require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bodyParser = require('body-parser');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.raw({ type: 'application/json' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.connect((err) => {
  if (err) {
    console.error('Error connecting to database:', err);
    process.exit(1);
  }
  console.log('Successfully connected to database!');
  pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(50) PRIMARY KEY,
      email VARCHAR(100) UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS wallets (
      id SERIAL PRIMARY KEY,
      user_id VARCHAR(50) NOT NULL,
      balance DECIMAL(10,2) NOT NULL DEFAULT 0.0,
      currency VARCHAR(3) NOT NULL,
      status VARCHAR(50) NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      payment_intent_id VARCHAR(100) UNIQUE,
      sender_id VARCHAR(50) NOT NULL,
      receiver_id VARCHAR(50) NOT NULL,
      amount DECIMAL(10,2) NOT NULL,
      currency VARCHAR(3) NOT NULL,
      status VARCHAR(50) NOT NULL,
      method VARCHAR(50) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (sender_id) REFERENCES users(id),
      FOREIGN KEY (receiver_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS payment_requests (
      id VARCHAR(36) PRIMARY KEY,
      requester_id VARCHAR(50) NOT NULL,
      target_id VARCHAR(50) NOT NULL,
      amount DECIMAL(10,2) NOT NULL,
      currency VARCHAR(3) NOT NULL,
      status VARCHAR(50) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (requester_id) REFERENCES users(id),
      FOREIGN KEY (target_id) REFERENCES users(id)
    );
  `, (err) => {
    if (err) console.error('Error creating tables:', err);
    else console.log('Tables ensured successfully!');
  });
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, claims) => {
    if (err || !claims) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.claims = claims;
    next();
  });
};

app.options('*', cors());

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ user_id: rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Error generating token' });
  }
});

app.post('/user-by-email', authenticateToken, async (req, res) => {
  const { email } = req.body;
  try {
    const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user_id: rows[0].id });
  } catch (err) {
    res.status(500).json({ error: 'Error querying user' });
  }
});

app.get('/wallet/balance', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT balance, currency FROM wallets WHERE user_id = $1 AND status = $2', [req.claims.user_id, 'active']);
    res.json(rows.map(row => ({ balance: row.balance, currency: row.currency })));
  } catch (err) {
    res.status(500).json({ error: 'Error querying wallets' });
  }
});

app.get('/payments/received', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT payment_intent_id, amount, currency, status, created_at FROM payments WHERE receiver_id = $1 AND status = $2',
      [req.claims.user_id, 'succeeded']
    );
    res.json(rows.map(row => ({
      paymentIntentId: row.payment_intent_id,
      amount: row.amount,
      currency: row.currency,
      status: row.status,
      createdAt: row.created_at.toISOString(),
    })));
  } catch (err) {
    res.status(500).json({ error: 'Error querying payments' });
  }
});

app.post('/create-payment', authenticateToken, async (req, res) => {
  const { amount, currency, user_id, target_id } = req.body;
  if (user_id !== req.claims.user_id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const pi = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100),
      currency,
      payment_method_types: ['card'],
    });
    const { rows } = await pool.query('SELECT EXISTS(SELECT 1 FROM payments WHERE payment_intent_id = $1)', [pi.id]);
    if (!rows[0].exists) {
      await pool.query(
        'INSERT INTO payments (payment_intent_id, sender_id, receiver_id, amount, currency, status, method) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [pi.id, user_id, target_id, amount, currency, pi.status, 'card']
      );
    }
    res.json({
      paymentIntentId: pi.id,
      amount,
      currency,
      status: pi.status,
      createdAt: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: `Error creating payment: ${err.message}` });
  }
});

app.post('/request-payment', authenticateToken, async (req, res) => {
  const { amount, currency, user_id, target_id } = req.body;
  if (user_id !== req.claims.user_id) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    await pool.query(
      'INSERT INTO payment_requests (id, requester_id, target_id, amount, currency, status) VALUES ($1, $2, $3, $4, $5, $6)',
      [uuidv4(), user_id, target_id, amount, currency, 'pending']
    );
    res.json({ status: 'request_created' });
  } catch (err) {
    res.status(500).json({ error: `Error inserting payment request: ${err.message}` });
  }
});

app.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    console.log('Webhook received:', event.type, event.data.object.id);
  } catch (err) {
    console.log('Webhook error:', err.message);
    return res.status(400).json({ error: `Webhook Error: ${err.message}` });
  }
  if (event.type === 'payment_intent.succeeded' || event.type === 'payment_intent.payment_failed') {
    const pi = event.data.object;
    const status = event.type === 'payment_intent.succeeded' ? 'succeeded' : 'failed';
    try {
      await pool.query('UPDATE payments SET status = $1 WHERE payment_intent_id = $2', [status, pi.id]);
      const clientWebhookUrl = process.env.CLIENT_WEBHOOK_URL;
      if (clientWebhookUrl) {
        await fetch(clientWebhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ event: event.type, paymentIntentId: pi.id, status }),
        });
      }
    } catch (err) {
      console.log('Error updating payment:', err.message);
      return res.status(500).json({ error: `Error updating payment status: ${err.message}` });
    }
  }
  res.json({ status: 'received' });
});

app.get('/list-payments', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT payment_intent_id, amount, currency, status, created_at FROM payments WHERE sender_id = $1 OR receiver_id = $1',
      [req.claims.user_id]
    );
    res.json(rows.map(row => ({
      paymentIntentId: row.payment_intent_id,
      amount: row.amount,
      currency: row.currency,
      status: row.status,
      createdAt: row.created_at.toISOString(),
    })));
  } catch (err) {
    res.status(500).json({ error: `Error querying payments: ${err.message}` });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));