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

// Store WebSocket clients with user_id
const clients = new Map();

wss.on('connection', (ws, req) => {
  console.log('WebSocket client connected');
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      if (data.user_id) {
        clients.set(data.user_id, ws); // Map user_id to WebSocket
        console.log(`WebSocket registered for user_id: ${data.user_id}`);
      }
    } catch (err) {
      console.error('WebSocket message error:', err);
    }
  });
  ws.on('close', () => {
    console.log('WebSocket client disconnected');
    for (const [user_id, client] of clients.entries()) {
      if (client === ws) {
        clients.delete(user_id);
        break;
      }
    }
  });
});
console.log('🪄 BUBBLES LIVE!'); // FORCE DEPLOY

// 🔓 CORS FIRST - UNLOCKS ALL DOORS!
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 'https://chatpay-frontend.onrender.com' : 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use((req, res, next) => {
  if (req.originalUrl === '/webhook') {
    next();
  } else {
    bodyParser.json()(req, res, next);
  }
});

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
      name VARCHAR(255) NOT NOT NULL,
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
      target_email VARCHAR(255)
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
    CREATE TABLE IF NOT EXISTS transactions (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      code VARCHAR(20) UNIQUE NOT NULL,
      requester_id uuid NOT NULL,
      sender_id uuid,
      amount NUMERIC(15,2) NOT NULL,
      currency VARCHAR(3) NOT NULL,
      status VARCHAR(20) DEFAULT 'pending',
      note TEXT,
      target_email VARCHAR(255),
      expires_at TIMESTAMP DEFAULT NOW() + INTERVAL '10 minutes',
      created_at TIMESTAMP DEFAULT NOW(),
      FOREIGN KEY (requester_id) REFERENCES users(id),
      FOREIGN KEY (sender_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id uuid NOT NULL,
      message TEXT NOT NULL,
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW(),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'payments' AND column_name = 'target_email'
        ) THEN
            ALTER TABLE payments ADD COLUMN target_email VARCHAR(255);
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'transactions' AND column_name = 'target_email'
        ) THEN
            ALTER TABLE transactions ADD COLUMN target_email VARCHAR(255);
        END IF;
    END $$;
  `, (err) => {
    if (err) console.error('Error creating tables:', err);
    else console.log('✅ Tables + TVC + notifications = READY!');
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

app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', process.env.NODE_ENV === 'production' ? 'https://chatpay-frontend.onrender.com' : 'http://localhost:3000');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.status(200).end();
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
    res.json({ token, user_id: rows[0].id });
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

app.post('/create-payment', authenticateToken, async (req, res) => {
  return res.status(403).json({ error: 'Direct payments disabled. Use /generate-tvc for secure transfers.' });
});

app.post('/generate-tvc', authenticateToken, async (req, res) => {
  const { amount, currency, target_email, note = '' } = req.body;
  const requester_id = req.claims.user_id;

  try {
    const { rows: targetUser } = await pool.query('SELECT id FROM users WHERE email = $1', [target_email]);
    if (targetUser.length === 0) return res.status(404).json({ error: 'User not found' });

    const { rows: requesterUser } = await pool.query('SELECT email FROM users WHERE id = $1', [requester_id]);
    const requester_email = requesterUser[0]?.email || 'unknown';

    const code = `CHAT-${Math.floor(100000 + Math.random() * 900000)}`;

    await pool.query(`
      INSERT INTO transactions (code, requester_id, amount, currency, note, status, target_email)
      VALUES ($1, $2, $3, $4, $5, 'pending', $6)
    `, [code, requester_id, amount, currency, note, target_email]);

    // Store notification for User B
    const target_id = targetUser[0].id;
    await pool.query(
      'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
      [target_id, `New Request: ₵${amount} ${currency} from ${requester_email} - Code: ${code}`]
    );

    // Notify User B via WebSocket
    const ws = clients.get(target_id);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        event: 'tvc_generated',
        code,
        amount,
        currency,
        requester_email,
        target_email,
        message: `New Request: ₵${amount} ${currency} from ${requester_email} - Code: ${code}`
      }));
    }

    res.json({ code, message: `Request sent! Code: ${code}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/confirm-tvc', authenticateToken, async (req, res) => {
  const { code } = req.body;
  const sender_id = req.claims.user_id;

  try {
    const { rows } = await pool.query(`
      SELECT * FROM transactions 
      WHERE code = $1 AND status = 'pending' AND expires_at > NOW()
    `, [code]);

    if (rows.length === 0) return res.status(400).json({ error: 'Invalid or expired code' });

    const { requester_id, amount, currency, target_email } = rows[0];

    const { rows: senderWallet } = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1 AND currency = $2 AND status = $3',
      [sender_id, currency, 'active']
    );
    if (senderWallet.length === 0 || senderWallet[0].balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    await pool.query(
      'UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND currency = $3 AND status = $4',
      [amount, sender_id, currency, 'active']
    );
    await pool.query(
      'UPDATE wallets SET balance = balance + $1 WHERE user_id = $2 AND currency = $3 AND status = $4',
      [amount, requester_id, currency, 'active']
    );

    await pool.query(
      'UPDATE transactions SET sender_id = $1, status = $2 WHERE code = $3',
      [sender_id, 'completed', code]
    );

    await pool.query(
      'INSERT INTO payments (payment_intent_id, amount, currency, sender_id, receiver_id, status, method, created_at, target_email) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)',
      [uuidv4(), amount, currency, sender_id, requester_id, 'succeeded', 'tvc', target_email]
    );

    // Mark notification as read
    await pool.query(
      'UPDATE notifications SET is_read = TRUE WHERE user_id = $1 AND message LIKE $2',
      [sender_id, `%Code: ${code}%`]
    );

    // Notify both users
    [sender_id, requester_id].forEach(user_id => {
      const ws = clients.get(user_id);
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          event: 'tvc_completed',
          code,
          amount,
          currency,
          from: sender_id,
          to: requester_id,
          message: `✅ ₵${amount} ${currency} transferred!`
        }));
      }
    });

    res.json({ success: true, message: `✅ ₵${amount} sent! Ref: ${code}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/notifications', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, message, created_at, is_read FROM notifications WHERE user_id = $1 AND is_read = FALSE ORDER BY created_at DESC',
      [req.claims.user_id]
    );
    res.json(rows.map(row => ({
      id: row.id,
      message: row.message,
      created_at: row.created_at.toISOString(),
      is_read: row.is_read
    })));
  } catch (err) {
    console.error('Notifications error:', err);
    res.status(500).json({ error: 'Error querying notifications' });
  }
});

app.post('/notifications/read', authenticateToken, async (req, res) => {
  try {
    const { notification_id } = req.body;
    await pool.query(
      'UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2',
      [notification_id, req.claims.user_id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Mark notification read error:', err);
    res.status(500).json({ error: 'Error marking notification as read' });
  }
});

app.get('/pending-tvc', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT t.code, t.amount, t.currency, t.status, t.note, t.created_at, u.email as requester_email
      FROM transactions t
      JOIN users u ON t.requester_id = u.id
      WHERE t.target_email = (SELECT email FROM users WHERE id = $1)
      AND t.status = 'pending' AND t.expires_at > NOW()
      ORDER BY t.created_at DESC
    `, [req.claims.user_id]);
    res.json(rows.map(row => ({
      code: row.code,
      amount: row.amount,
      currency: row.currency,
      status: row.status,
      requester_email: row.requester_email,
      created_at: row.created_at.toISOString(),
    })));
  } catch (err) {
    console.error('Pending TVC error:', err);
    res.status(500).json({ error: 'Error querying pending TVC' });
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
          'INSERT INTO payments (payment_intent_id, amount, currency, sender_id, receiver_id, status, method, created_at, target_email) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
          [pi.id, pi.amount / 100, pi.currency, '550e8400-e29b-41d4-a716-446655440000', '550e8400-e29b-41d4-a716-446655440000', status, 'card', new Date(), null]
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
      `SELECT payment_intent_id, amount, currency, status, created_at, target_email 
       FROM payments 
       WHERE sender_id = $1 OR receiver_id = $1 
       ORDER BY created_at DESC`,
      [req.claims.user_id]
    );
    res.json(rows.map(row => ({
      payment_intent_id: row.payment_intent_id,
      amount: row.amount,
      currency: row.currency,
      status: row.status,
      target_email: row.target_email || null,
      created_at: row.created_at.toISOString(),
    })));
  } catch (err) {
    console.error('List payments error:', err);
    res.status(500).json({ error: `Error querying payments: ${err.message}` });
  }
});

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

app.post('/signin', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const { rows } = await pool.query(
      'SELECT id, password FROM users WHERE email = $1',
      [email]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const validPassword = await bcrypt.compare(password, rows[0].password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const userId = rows[0].id;
    const token = jwt.sign(
      { user_id: userId },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '1h' }
    );
    const { rows: walletRows } = await pool.query(
      'SELECT id FROM wallets WHERE user_id = $1 AND currency = $2',
      [userId, 'EUR']
    );
    if (walletRows.length === 0) {
      await pool.query(
        `INSERT INTO wallets (id, user_id, balance, currency, status)
         VALUES (gen_random_uuid(), $1, 0, $2, $3)`,
        [userId, 'EUR', 'active']
      );
    }
    res.json({
      message: 'Signin successful',
      token,
      user_id: userId,
    });
  } catch (err) {
    console.error('❌ /signin error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/request-payment', authenticateToken, async (req, res) => {
  const { amount, currency, target_email } = req.body;
  const user_id = req.claims.user_id;
  try {
    const { rows: targetUser } = await pool.query('SELECT id FROM users WHERE email = $1', [target_email]);
    if (targetUser.length === 0) {
      return res.status(404).json({ error: 'Target user not found' });
    }
    const target_id = targetUser[0].id;

    await pool.query(
      'INSERT INTO payment_requests (id, requester_id, target_id, amount, currency, status) VALUES ($1, $2, $3, $4, $5, $6)',
      [uuidv4(), user_id, target_id, amount, currency, 'pending']
    );

    const { rows: requesterUser } = await pool.query('SELECT email FROM users WHERE id = $1', [user_id]);
    const requester_email = requesterUser[0]?.email || 'unknown';

    // Store notification for User B
    await pool.query(
      'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
      [target_id, `Payment requested: ${amount} ${currency} from ${requester_email}`]
    );

    // Notify User B via WebSocket
    const ws = clients.get(target_id);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        event: 'payment_requested',
        amount,
        currency,
        requester_email,
        message: `Payment requested: ${amount} ${currency} from ${requester_email}`
      }));
    }

    res.json({ status: 'request_created' });
  } catch (err) {
    res.status(500).json({ error: `Error: ${err.message}` });
  }
});

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
      language: 'en',
      name: rows[0].name,
      email: rows[0].email
    });
  } catch (err) {
    res.status(500).json({ error: 'Error fetching preferences' });
  }
});

app.post('/crypto-transfer', authenticateToken, async (req, res) => {
  try {
    const { to_address, amount, currency } = req.body;
    const user_id = req.claims.user_id;

    const { rows: walletRows } = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1 AND currency = $2 AND status = $3',
      [user_id, currency, 'active']
    );
    if (walletRows.length === 0 || walletRows[0].balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const txHash = `tx_${uuidv4().slice(0, 8)}`;

    await pool.query(
      'UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND currency = $3 AND status = $4',
      [amount, user_id, currency, 'active']
    );

    await pool.query(
      'INSERT INTO payments (payment_intent_id, amount, currency, sender_id, status, method, created_at, target_email) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [txHash, amount, currency, user_id, 'succeeded', 'crypto', new Date(), to_address]
    );

    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          event: 'crypto_sent',
          type: 'crypto_sent',
          amount,
          to: to_address,
          txHash,
          timestamp: new Date()
        }));
      }
    });

    res.json({
      message: `₿ ${amount} ${currency} sent! Tx: ${txHash}`,
      txHash
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/transfer', authenticateToken, async (req, res) => {
  try {
    const { to_wallet, amount } = req.body;
    const from_wallet = req.claims.user_id;

    const { rows: fromWallet } = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1 AND currency = $2',
      [from_wallet, 'EUR']
    );
    const { rows: toWallet } = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1 AND currency = $2',
      [to_wallet, 'EUR']
    );

    if (fromWallet.length === 0 || fromWallet[0].balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    await pool.query(
      'UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND currency = $3',
      [amount, from_wallet, 'EUR']
    );
    await pool.query(
      'UPDATE wallets SET balance = balance + $1 WHERE user_id = $2 AND currency = $3',
      [amount, to_wallet, 'EUR']
    );

    res.json({ message: `✅ ${amount} transferred to ${to_wallet}` });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`Server running on port ${port}`));