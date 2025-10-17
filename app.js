// Force commit for Render deployment with updated env handling
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || '');
const bodyParser = require('body-parser');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

wss.on('connection', (ws) => {
  console.log('WebSocket client connected');
  ws.on('close', () => console.log('WebSocket client disconnected'));
});

console.log('🪄 BUBBLES LIVE!');  // FORCE DEPLOY
// Enable CORS for all routes except webhook
app.use((req, res, next) => {
  if (req.originalUrl === '/webhook') {
    next();
  } else {
    cors()(req, res, next);
  }
});

// Use JSON parsing for all routes except /webhook
app.use((req, res, next) => {
  if (req.originalUrl === '/webhook') {
    next();
  } else {
    bodyParser.json()(req, res, next);
  }
});

// Use raw body parsing for /webhook
app.use('/webhook', bodyParser.raw({ type: 'application/json' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/chatpay_db',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : { rejectUnauthorized: false },
  connectionTimeoutMillis: 5000,
  max: 10,
  idleTimeoutMillis: 30000,
});

pool.connect((err) => {
  if (err) {
    console.error('Error connecting to database:', err);
    process.exit(1);
  }
  console.log('Successfully connected to database!');
  pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name VARCHAR(255) NOT NULL,
      surname VARCHAR(255) NOT NULL,
      gender VARCHAR(50),
      phone VARCHAR(20),
      dob DATE,
      reset_token VARCHAR(255),
      reset_token_expiry TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS wallets (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id uuid NOT NULL,
      balance NUMERIC(15,2) DEFAULT 0,
      currency VARCHAR(3) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      created_at TIMESTAMP DEFAULT NOW(),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      CONSTRAINT wallets_user_id_currency_key UNIQUE (user_id, currency)
    );
    CREATE TABLE IF NOT EXISTS payments (
      payment_intent_id VARCHAR(255) PRIMARY KEY,
      amount NUMERIC(15,2) NOT NULL,
      currency VARCHAR(3) NOT NULL,
      sender_id uuid,
      receiver_id uuid,
      status VARCHAR(50) NOT NULL DEFAULT 'succeeded',
      method VARCHAR(50) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS payment_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_id uuid,
  target_id uuid,
  amount NUMERIC(15,2) NOT NULL,
  currency VARCHAR(3) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE

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

app.options('*', (req, res, next) => {
  if (req.originalUrl === '/webhook') {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Stripe-Signature');
    res.status(200).end();
  } else {
    cors()(req, res, next);
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

app.post('/signup', async (req, res) => {
  const { email, password, name, surname } = req.body;
  try {
    const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (rows.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    await pool.query(
      'INSERT INTO users (id, email, password, name, surname) VALUES ($1, $2, $3, $4, $5)',
      [userId, email, hashedPassword, name, surname]
    );
    const token = jwt.sign({ user_id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: `Error creating user: ${err.message}` });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT id, password FROM users WHERE email = $1', [email]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const validPassword = await bcrypt.compare(password, rows[0].password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ user_id: rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Error generating token' });
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

// 🔥 FIXED create-payment (ONLY 2 LINES CHANGED!)
app.post('/create-payment', authenticateToken, async (req, res) => {
  const { amount, currency, target_id } = req.body;
  // 🔥 FIX 1: Use token user_id (ignore body user_id)
  const user_id = req.claims.user_id;
  
  try {
    // Ensure sender has wallet
    const { rows: senderWallet } = await pool.query(
      'SELECT id FROM wallets WHERE user_id = $1 AND currency = $2',
      [user_id, currency]
    );
    if (senderWallet.length === 0) {
      await pool.query(
        'INSERT INTO wallets (id, user_id, balance, currency, status) VALUES (gen_random_uuid(), $1, 0, $2, $3)',
        [user_id, currency, 'active']
      );
    }
    const pi = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100),
      currency,
      payment_method_types: ['card'],
    });
    const { rows } = await pool.query('SELECT EXISTS(SELECT 1 FROM payments WHERE payment_intent_id = $1)', [pi.id]);
    if (!rows[0].exists) {
      await pool.query(
        'INSERT INTO payments (payment_intent_id, amount, currency, sender_id, receiver_id, status, method) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [pi.id, amount, currency, user_id, target_id, pi.status, 'card']  // 🔥 FIX 2: Use token user_id
      );
    }
    // Notify via WebSocket
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ 
          event: 'payment_sent', 
          paymentIntentId: pi.id, 
          amount, 
          currency,
          message: `Payment sent: ${amount} ${currency}`
        }));
      }
    });
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
      const { rows } = await pool.query('SELECT EXISTS(SELECT 1 FROM payments WHERE payment_intent_id = $1)', [pi.id]);
      if (rows[0].exists) {
        await pool.query('UPDATE payments SET status = $1 WHERE payment_intent_id = $2', [status, pi.id]);
      } else {
        await pool.query(
          'INSERT INTO payments (payment_intent_id, amount, currency, sender_id, receiver_id, status, method, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
          [pi.id, pi.amount / 100, pi.currency, '550e8400-e29b-41d4-a716-446655440000', '550e8400-e29b-41d4-a716-446655440000', status, 'card', new Date()]
        );
      }
      wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ event: event.type, paymentIntentId: pi.id, status }));
        }
      });
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

// 🔥 RESTORE MISSING ENDPOINTS FOR BUBBLES
app.get('/recent-transactions', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT payment_intent_id, amount, currency, status, created_at FROM payments WHERE sender_id = $1 OR receiver_id = $1 ORDER BY created_at DESC LIMIT 10',
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
    res.status(500).json({ error: 'Error fetching transactions' });
  }
});

app.post('/withdraw-wallet', authenticateToken, async (req, res) => {
  const { amount, currency } = req.body;
  try {
    const { rows: walletRows } = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1 AND currency = $2 AND status = $3',
      [req.claims.user_id, currency, 'active']
    );
    if (walletRows.length === 0 || walletRows[0].balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    await pool.query(
      'UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND currency = $3 AND status = $4',
      [amount, req.claims.user_id, currency, 'active']
    );
    // Create wallet debit record
    await pool.query(
      'INSERT INTO payments (payment_intent_id, amount, currency, sender_id, status, method, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [uuidv4(), amount, currency, req.claims.user_id, 'succeeded', 'withdraw', new Date()]
    );
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ 
          event: 'wallet_debited', 
          amount, 
          currency, 
          message: `Wallet debited: -${amount} ${currency}` 
        }));
      }
    });
    res.json({ success: true, message: `Withdrew ${amount} ${currency}` });
  } catch (err) {
    res.status(500).json({ error: 'Withdraw failed' });
  }
});

// 🔥 ADD auto-wallet creation on user login
app.post('/signin', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT id, password FROM users WHERE email = $1', [email]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const validPassword = await bcrypt.compare(password, rows[0].password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ user_id: rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    
    // CREATE WALLET AUTOMATICALLY (was missing!)
    const { rows: walletRows } = await pool.query(
      'SELECT id FROM wallets WHERE user_id = $1 AND currency = $2',
      [rows[0].id, 'EUR']
    );
    if (walletRows.length === 0) {
      await pool.query(
        'INSERT INTO wallets (id, user_id, balance, currency, status) VALUES (gen_random_uuid(), $1, 0, $2, $3)',
        [rows[0].id, 'EUR', 'active']
      );
    }
    
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Error generating token' });
  }
});

 // 🔥 SECURE FIX: Request Payment (Email → Real UUID)
app.post('/request-payment', authenticateToken, async (req, res) => {
  const { amount, currency, target_email } = req.body;  // ← EMAIL not ID!
  const user_id = req.claims.user_id;
  
  try {
    // 🔐 SECURE: Lookup REAL user by email
    const { rows: targetUser } = await pool.query('SELECT id FROM users WHERE email = $1', [target_email]);
    if (targetUser.length === 0) {
      return res.status(404).json({ error: 'Target user not found' });
    }
    const target_id = targetUser[0].id;  // ← REAL UUID!
    
    await pool.query(
      'INSERT INTO payment_requests (id, requester_id, target_id, amount, currency, status) VALUES ($1, $2, $3, $4, $5, $6)',
      [uuidv4(), user_id, target_id, amount, currency, 'pending']
    );
    
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ 
          event: 'payment_requested', 
          amount, 
          currency, 
          message: `Payment requested: ${amount} ${currency} to ${target_email}` 
        }));
      }
    });
    res.json({ status: 'request_created' });
  } catch (err) {
    res.status(500).json({ error: `Error: ${err.message}` });
  }
});

// 🔥 FIX 2: Fund Wallet (No Response → 200)
app.post('/fund-wallet', authenticateToken, async (req, res) => {
  const { amount, currency } = req.body;
  try {
    const { rows: walletRows } = await pool.query(
      'SELECT id FROM wallets WHERE user_id = $1 AND currency = $2',
      [req.claims.user_id, currency]
    );
    if (walletRows.length === 0) {
      await pool.query(
        'INSERT INTO wallets (id, user_id, balance, currency, status) VALUES (gen_random_uuid(), $1, 0, $2, $3)',
        [req.claims.user_id, currency, 'active']
      );
    }
    await pool.query(
      'UPDATE wallets SET balance = balance + $1 WHERE user_id = $2 AND currency = $3 AND status = $4',
      [amount, req.claims.user_id, currency, 'active']
    );
    await pool.query(
      'INSERT INTO payments (payment_intent_id, amount, currency, sender_id, status, method, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [uuidv4(), amount, currency, req.claims.user_id, 'succeeded', 'fund', new Date()]
    );
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ event: 'wallet_funded', amount, currency, message: `Wallet funded: +${amount} ${currency}` }));
      }
    });
    res.json({ success: true, message: `Funded ${amount} ${currency}` });
  } catch (err) {
    res.status(500).json({ error: 'Funding failed' });
  }
});

// 🔥 FIX 3: User Preferences (404 → 200)
app.get('/user/preferences', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.claims.user_id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      notificationsEnabled: true,
      theme: 'day',
      currency: 'EUR',
      language: 'en'
    });
  } catch (err) {
    res.status(500).json({ error: 'Error fetching preferences' });
  }
});
const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`Server running on port ${port}`));