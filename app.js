// server/app.js
console.log('TVC FLOW LIVE!');
// Force commit for Render deployment
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

// STORE CONNECTIONS BY CONVERSATION
const conversations = {}; // { convId: [ws1, ws2] }

wss.on('connection', (ws, req) => {
  console.log('WebSocket client connected');

  // JOIN CONVERSATION
  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      if (msg.type === 'join') {
        const convId = msg.conversation_id;
        if (!conversations[convId]) {
          conversations[convId] = [];
        }
        conversations[convId].push(ws);
        console.log(`User joined conversation: ${convId}`);
      }
    } catch (err) {
      console.error('Join error:', err);
    }
  });

  // SEND MESSAGE TO CONVERSATION
  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      const convId = msg.conversation_id;
      
      if (conversations[convId]) {
        conversations[convId].forEach(client => {
          if (client.readyState === WebSocket.OPEN && client !== ws) {
            client.send(data); // ONLY TO OTHERS IN GROUP!
          }
        });
      }
    } catch (err) {
      console.error('Message error:', err);
    }
  });

  // CLEAN UP ON CLOSE
  ws.on('close', () => {
    Object.keys(conversations).forEach(convId => {
      conversations[convId] = conversations[convId].filter(client => client !== ws);
    });
  });
});

console.log('BUBBLES LIVE!');

// CORS — FIXED FOR LOCAL TESTING!
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      'https://chatpay-frontend.onrender.com',
      'http://localhost:3000',
      'http://127.0.0.1:3000'
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use((req, res, next) => {
  if (req.originalUrl === '/webhook') next();
  else bodyParser.json()(req, res, next);
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
    console.error('DB error:', err);
    process.exit(1);
  }
  console.log('DB connected!');
  pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name VARCHAR(255) NOT NULL,
      surname VARCHAR(255) NOT NULL,
      phone VARCHAR(20),
      gender VARCHAR(50),
      dob DATE
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
  `, (err) => {
    if (err) console.error('Table creation error:', err);
    else console.log('Tables ready!');
  });
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, claims) => {
    if (err || !claims) return res.status(401).json({ error: 'Invalid token' });
    req.claims = claims;
    next();
  });
};

// === RESTORED: /signin (EXACTLY AS BEFORE) ===
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

// === TVC: DIRECT SEND (SENDER → RECEIVER) ===
app.post('/generate-tvc', authenticateToken, async (req, res) => {
  const { amount, currency, target_email, note = '' } = req.body;
  const sender_id = req.claims.user_id;
  try {
    const { rows: targetUser } = await pool.query('SELECT id FROM users WHERE email = $1', [target_email]);
    if (targetUser.length === 0) return res.status(404).json({ error: 'User not found' });
    const target_id = targetUser[0].id;
    const sender_email = (await pool.query('SELECT email FROM users WHERE id = $1', [sender_id])).rows[0].email;
    const code = `CHAT-${Math.floor(100000 + Math.random() * 900000)}`;
    await pool.query(`
      INSERT INTO transactions (code, requester_id, amount, currency, status, target_email, note)
      VALUES ($1, $2, $3, $4, 'pending', $5, $6)
    `, [code, sender_id, amount, currency, target_email, `Direct send from ${sender_email}`]);
    const message = `You received ₵${amount} ${currency} from ${sender_email} - Code: ${code}`;
    await pool.query('INSERT INTO notifications (user_id, message) VALUES ($1, $2)', [target_id, message]);
    const ws = clients.get(target_id);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ event: 'tvc_received', code, amount, currency, from: sender_email, message }));
    }
    res.json({ code, message: `TVC sent to ${target_email}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// === TVC: REQUEST PAYMENT (REQUESTER → PAYER) ===
app.post('/request-payment', authenticateToken, async (req, res) => {
  const { amount, currency, target_email } = req.body;
  const requester_id = req.claims.user_id;
  try {
    const { rows: targetUser } = await pool.query('SELECT id FROM users WHERE email = $1', [target_email]);
    if (targetUser.length === 0) return res.status(404).json({ error: 'User not found' });
    const target_id = targetUser[0].id;
    const requester_email = (await pool.query('SELECT email FROM users WHERE id = $1', [requester_id])).rows[0].email;
    const code = `CHAT-${Math.floor(100000 + Math.random() * 900000)}`;
    await pool.query(`
      INSERT INTO transactions (code, requester_id, amount, currency, status, target_email, note)
      VALUES ($1, $2, $3, $4, 'pending', $5, $6)
    `, [code, requester_id, amount, currency, target_email, `Request from ${requester_email}`]);
    const message = `Payment request: ₵${amount} ${currency} from ${requester_email} - Code: ${code}`;
    await pool.query('INSERT INTO notifications (user_id, message) VALUES ($1, $2)', [target_id, message]);
    const ws = clients.get(target_id);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ event: 'tvc_requested', code, amount, currency, from: requester_email, message }));
    }
    res.json({ success: true, message: `Request sent to ${target_email}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// === TVC: CONFIRM WITH EMAIL OR PHONE ===
app.post('/confirm-tvc', authenticateToken, async (req, res) => {
  const { code, identifier } = req.body;
  const user_id = req.claims.user_id;
  try {
    const { rows } = await pool.query(`
      SELECT t.*, u.email, u.phone FROM transactions t
      JOIN users u ON t.requester_id = u.id
      WHERE t.code = $1 AND t.status = 'pending' AND t.expires_at > NOW()
    `, [code]);
    if (rows.length === 0) return res.status(400).json({ error: 'Invalid or expired code' });
    const tx = rows[0];
    const isEmailMatch = tx.target_email === identifier;
    const isPhoneMatch = tx.phone === identifier;
    if (!isEmailMatch && !isPhoneMatch) {
      return res.status(403).json({ error: 'Email or phone does not match recipient' });
    }
    await pool.query('UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND currency = $3', [tx.amount, user_id, tx.currency]);
    await pool.query('UPDATE wallets SET balance = balance + $1 WHERE user_id = $2 AND currency = $3', [tx.amount, tx.requester_id, tx.currency]);
    await pool.query('UPDATE transactions SET status = $1, sender_id = $2 WHERE code = $3', ['completed', user_id, code]);
    await pool.query('UPDATE notifications SET is_read = TRUE WHERE message LIKE $1', [`%${code}%`]);
    res.json({ success: true, message: `₵${tx.amount} received!` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// === NOTIFICATIONS ENDPOINT ===
app.get('/notifications', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, message, created_at FROM notifications WHERE user_id = $1 AND is_read = FALSE ORDER BY created_at DESC',
      [req.claims.user_id]
    );
    res.json(rows.map(r => ({ id: r.id, message: r.message, created_at: r.created_at.toISOString() })));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// === MARK NOTIFICATION AS READ (NOW WITH CATCH!) ===
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
    await pool.query(
      'INSERT INTO notifications (user_id, message, created_at) VALUES ($1, $2, NOW())',
      [target_id, `Payment requested: ${amount} ${currency} from ${requester_email}`]
    );
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