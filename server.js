const express    = require('express');
const nodemailer = require('nodemailer');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Config ────────────────────────────────────────────────────────────────────
const GMAIL_USER       = process.env.GMAIL_USER       || '';
const GMAIL_PASS       = process.env.GMAIL_PASS       || '';
const NOTIFY_EMAIL     = process.env.NOTIFY_EMAIL     || '';
const DASHBOARD_PASS   = process.env.DASHBOARD_PASS   || 'ig2024';
const LS_WEBHOOK_SECRET = process.env.LS_WEBHOOK_SECRET || '';

// ── Data files ────────────────────────────────────────────────────────────────
const DATA_DIR      = path.join(__dirname, 'data');
const CONTACTS_FILE = path.join(DATA_DIR, 'contacts.json');
const KEYS_FILE     = path.join(DATA_DIR, 'licenses.json');

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(CONTACTS_FILE)) fs.writeFileSync(CONTACTS_FILE, '[]');
if (!fs.existsSync(KEYS_FILE))     fs.writeFileSync(KEYS_FILE,     '[]');

// ── Middleware ────────────────────────────────────────────────────────────────
// Raw body needed for webhook signature verification
app.use('/api/lemonsqueezy/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS — allow your Vercel site
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── Mailer ────────────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: GMAIL_USER, pass: GMAIL_PASS }
});

function sendEmail(to, subject, html) {
  return transporter.sendMail({
    from: `"Incognito Guard" <${GMAIL_USER}>`,
    to,
    subject,
    html
  });
}

function notifyOwner(subject, html) {
  return sendEmail(NOTIFY_EMAIL, subject, html);
}

// ── Data helpers ──────────────────────────────────────────────────────────────
function loadContacts() {
  try { return JSON.parse(fs.readFileSync(CONTACTS_FILE, 'utf8')); }
  catch (_) { return []; }
}
function saveContacts(data) {
  fs.writeFileSync(CONTACTS_FILE, JSON.stringify(data, null, 2));
}

function loadKeys() {
  try { return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8')); }
  catch (_) { return []; }
}
function saveKeys(data) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(data, null, 2));
}

function generateKey() {
  const seg = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `IG-${seg()}-${seg()}-${seg()}`;
}

// ── Routes ────────────────────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'Incognito Guard Server running', time: new Date().toISOString() });
});

// ── POST /api/contact ─────────────────────────────────────────────────────────
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, subject, os, message } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }

    const entry = {
      id:         crypto.randomUUID(),
      name, email, subject, os, message,
      receivedAt: new Date().toISOString()
    };

    const contacts = loadContacts();
    contacts.unshift(entry);
    saveContacts(contacts);

    // Notify owner
    await notifyOwner(
      `🛡 IG Contact — ${subject} from ${name}`,
      `<div style="font-family:sans-serif;max-width:600px;margin:0 auto;">
        <div style="background:#0a0a0b;padding:24px;border-radius:12px 12px 0 0;">
          <h2 style="color:#ff3e5e;margin:0;">Incognito Guard — New Contact</h2>
        </div>
        <div style="background:#f9f9f9;padding:24px;border-radius:0 0 12px 12px;">
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p>
          <p><strong>Subject:</strong> ${subject}</p>
          <p><strong>OS:</strong> ${os || 'Not specified'}</p>
          <p style="margin-top:12px;"><strong>Message:</strong><br/>${message}</p>
          <hr style="margin:16px 0;border:none;border-top:1px solid #ddd;"/>
          <p style="color:#999;font-size:12px;">Received: ${entry.receivedAt}</p>
        </div>
      </div>`
    );

    res.json({ success: true, id: entry.id });
  } catch (err) {
    console.error('Contact error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/lemonsqueezy/webhook ────────────────────────────────────────────
app.post('/api/lemonsqueezy/webhook', async (req, res) => {
  try {
    // Verify signature
    if (LS_WEBHOOK_SECRET) {
      const signature = req.headers['x-signature'];
      const hmac      = crypto.createHmac('sha256', LS_WEBHOOK_SECRET);
      hmac.update(req.body);
      const digest = hmac.digest('hex');
      if (digest !== signature) {
        console.error('Invalid webhook signature');
        return res.status(401).json({ error: 'Invalid signature' });
      }
    }

    const payload = JSON.parse(req.body);
    const event   = payload.meta?.event_name;

    console.log('LS webhook event:', event);

    if (event !== 'order_created') return res.json({ received: true });

    const order   = payload.data?.attributes;
    const email   = order?.user_email;
    const orderId = String(payload.data?.id);

    if (!email) return res.status(400).json({ error: 'No email in payload' });

    // Prevent duplicate keys
    const keys     = loadKeys();
    const existing = keys.find(k => k.orderId === orderId);
    if (existing) {
      console.log('Key already issued for order', orderId);
      return res.json({ received: true, note: 'Key already issued' });
    }

    // Generate key
    const key   = generateKey();
    const entry = {
      key,
      email,
      orderId,
      createdAt:   new Date().toISOString(),
      activatedAt: null,
      machine:     null,
      revoked:     false,
      source:      'lemonsqueezy'
    };
    keys.push(entry);
    saveKeys(keys);

    // Email key to customer
    await sendEmail(
      email,
      '🛡 Your Incognito Guard Pro License Key',
      `<div style="font-family:sans-serif;max-width:600px;margin:0 auto;">
        <div style="background:#0a0a0b;padding:24px;border-radius:12px 12px 0 0;">
          <h2 style="color:#ff3e5e;margin:0;">Your Incognito Guard Pro License</h2>
        </div>
        <div style="background:#f9f9f9;padding:32px;border-radius:0 0 12px 12px;">
          <p style="margin-bottom:16px;">Thank you for purchasing Incognito Guard Pro! 🎉</p>
          <p>Your license key:</p>
          <div style="background:#0a0a0b;color:#ff3e5e;font-family:monospace;
            font-size:22px;padding:20px;border-radius:8px;margin:16px 0;
            letter-spacing:0.15em;text-align:center;">
            ${key}
          </div>
          <p style="font-weight:bold;margin-bottom:8px;">How to activate:</p>
          <ol style="margin:8px 0 16px 20px;line-height:2.2;">
            <li>Download Incognito Guard from your receipt page</li>
            <li>Open the app and click <strong>⚙ Settings</strong></li>
            <li>Enter your license key above</li>
            <li>Click <strong>Activate Pro</strong> — email alerts are now active!</li>
          </ol>
          <hr style="border:none;border-top:1px solid #eee;margin:20px 0;"/>
          <p style="color:#999;font-size:12px;">
            Order ID: ${orderId}<br/>
            Need help? Reply to this email or visit
            <a href="https://incognito-guard.vercel.app/ig-contact.html">incognito-guard.vercel.app</a>
          </p>
          <p style="color:#ccc;font-size:11px;margin-top:16px;">
            Built for parents who care. — Incognito Guard
          </p>
        </div>
      </div>`
    );

    // Notify owner of sale
    await notifyOwner(
      `💰 New Incognito Guard Sale — $19.99 from ${email}`,
      `<div style="font-family:sans-serif;max-width:600px;">
        <div style="background:#0a0a0b;padding:24px;border-radius:12px 12px 0 0;">
          <h2 style="color:#ff3e5e;margin:0;">New Sale! 🎉</h2>
        </div>
        <div style="background:#f9f9f9;padding:24px;border-radius:0 0 12px 12px;">
          <p><strong>Customer:</strong> ${email}</p>
          <p><strong>Key issued:</strong> ${key}</p>
          <p><strong>Order ID:</strong> ${orderId}</p>
          <p><strong>Date:</strong> ${new Date().toISOString()}</p>
        </div>
      </div>`
    );

    console.log(`Key ${key} issued to ${email}`);
    res.json({ success: true });

  } catch (err) {
    console.error('LS webhook error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/activate — validate license key from guard.py ──────────────────
app.post('/api/activate', (req, res) => {
  const { key, machine } = req.body;
  if (!key) return res.status(400).json({ success: false, error: 'No key provided.' });

  const keys  = loadKeys();
  const entry = keys.find(k => k.key === key.trim().toUpperCase());

  if (!entry)        return res.json({ success: false, error: 'Invalid license key.' });
  if (entry.revoked) return res.json({ success: false, error: 'This license has been revoked.' });
  if (entry.activatedAt && entry.machine && entry.machine !== machine) {
    return res.json({ success: false, error: 'Key already activated on another machine. Contact support.' });
  }

  if (!entry.activatedAt) {
    entry.activatedAt = new Date().toISOString();
    entry.machine     = machine || 'unknown';
    saveKeys(keys);
  }

  res.json({ success: true, tier: 'pro', activatedAt: entry.activatedAt });
});

// ── GET /dashboard ────────────────────────────────────────────────────────────
app.get('/dashboard', (req, res) => {
  const pass = req.query.pass;

  if (pass !== DASHBOARD_PASS) {
    return res.send(`
      <html><body style="font-family:sans-serif;display:flex;align-items:center;
        justify-content:center;height:100vh;margin:0;background:#0a0a0b;">
        <form method="GET" action="/dashboard"
          style="background:#16161a;padding:32px;border-radius:12px;
          border:1px solid #252529;display:flex;flex-direction:column;gap:12px;min-width:300px;">
          <h2 style="color:#e8e8f0;margin:0;">🛡 IG Dashboard</h2>
          <p style="color:#5a5a6e;font-size:13px;margin:0;">Enter your dashboard password</p>
          <input name="pass" type="password" placeholder="Password"
            style="padding:10px;border-radius:8px;border:1px solid #3a3a42;
            background:#0a0a0b;color:#e8e8f0;font-size:14px;outline:none;"/>
          <button type="submit"
            style="padding:10px;border-radius:8px;background:#ff3e5e;
            border:none;color:#fff;font-weight:700;cursor:pointer;font-size:14px;">
            Enter
          </button>
        </form>
      </body></html>
    `);
  }

  const contacts = loadContacts();
  const keys     = loadKeys();
  const activated = keys.filter(k => k.activatedAt).length;
  const pending   = keys.filter(k => !k.activatedAt && !k.revoked).length;
  const revenue   = keys.filter(k => k.source === 'lemonsqueezy').length * 19.99;

  const keyRows = keys.slice().reverse().map(k => `
    <tr style="border-bottom:1px solid #252529;">
      <td style="padding:10px;font-family:monospace;font-size:11px;color:#ff3e5e;">${k.key}</td>
      <td style="padding:10px;font-size:12px;color:#5a5a6e;">${k.email || '—'}</td>
      <td style="padding:10px;">
        <span style="padding:2px 8px;border-radius:4px;font-size:11px;
          background:${k.revoked ? 'rgba(255,68,102,0.1)' : k.activatedAt ? 'rgba(0,229,160,0.1)' : 'rgba(255,255,255,0.05)'};
          color:${k.revoked ? '#ff4466' : k.activatedAt ? '#00e5a0' : '#5a5a6e'};">
          ${k.revoked ? 'Revoked' : k.activatedAt ? 'Active' : 'Pending'}
        </span>
      </td>
      <td style="padding:10px;font-size:11px;color:#5a5a6e;">${k.machine || '—'}</td>
      <td style="padding:10px;font-size:11px;color:#5a5a6e;">${k.activatedAt ? k.activatedAt.slice(0,10) : '—'}</td>
    </tr>
  `).join('');

  const contactRows = contacts.map(c => `
    <tr style="border-bottom:1px solid #252529;">
      <td style="padding:10px;font-size:13px;">${c.name}</td>
      <td style="padding:10px;"><a href="mailto:${c.email}" style="color:#38b6ff;font-size:12px;">${c.email}</a></td>
      <td style="padding:10px;font-size:12px;color:#5a5a6e;">${c.subject}</td>
      <td style="padding:10px;font-size:11px;color:#5a5a6e;">${c.os || '—'}</td>
      <td style="padding:10px;font-size:11px;color:#5a5a6e;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${c.message}</td>
      <td style="padding:10px;font-size:11px;color:#5a5a6e;">${c.receivedAt?.slice(0,10)}</td>
    </tr>
  `).join('');

  res.send(`
    <html>
    <head>
      <title>Incognito Guard Dashboard</title>
      <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:sans-serif;background:#0a0a0b;color:#e8e8f0;min-height:100vh;}
        .header{background:#16161a;border-bottom:1px solid #252529;padding:20px 32px;
          display:flex;align-items:center;justify-content:space-between;}
        .logo{font-size:20px;font-weight:800;}
        .logo span{color:#ff3e5e;}
        .stats{display:flex;gap:20px;padding:28px 32px 0;flex-wrap:wrap;}
        .stat{background:#16161a;border:1px solid #252529;border-radius:12px;padding:20px 28px;flex:1;min-width:130px;}
        .stat-val{font-size:30px;font-weight:800;color:#ff3e5e;}
        .stat-val.green{color:#00e5a0;}
        .stat-label{font-size:11px;color:#5a5a6e;margin-top:4px;text-transform:uppercase;letter-spacing:0.1em;}
        .section{padding:28px 32px;}
        .section-title{font-size:12px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;color:#5a5a6e;margin-bottom:14px;}
        .table-wrap{overflow-x:auto;margin-bottom:28px;}
        table{width:100%;border-collapse:collapse;background:#16161a;border:1px solid #252529;border-radius:12px;overflow:hidden;}
        th{padding:12px;text-align:left;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;color:#5a5a6e;border-bottom:1px solid #252529;}
        .gen-form{background:#16161a;border:1px solid #252529;border-radius:12px;padding:20px;
          display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin-bottom:20px;}
        .gen-form input{background:#0a0a0b;border:1px solid #3a3a42;border-radius:8px;
          color:#e8e8f0;font-size:13px;padding:8px 12px;outline:none;}
        .gen-form button{background:#ff3e5e;border:none;border-radius:8px;color:#fff;
          font-weight:700;font-size:13px;padding:9px 20px;cursor:pointer;}
        .gen-form label{font-size:10px;color:#5a5a6e;display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.1em;}
      </style>
    </head>
    <body>
      <div class="header">
        <div class="logo">🛡 INCOGNITO<span>GUARD</span> Dashboard</div>
        <div style="font-size:12px;color:#5a5a6e;">${new Date().toLocaleDateString()}</div>
      </div>

      <div class="stats">
        <div class="stat"><div class="stat-val">${keys.length}</div><div class="stat-label">Total Keys</div></div>
        <div class="stat"><div class="stat-val green">${activated}</div><div class="stat-label">Activated</div></div>
        <div class="stat"><div class="stat-val" style="color:#f9ca24;">${pending}</div><div class="stat-label">Pending</div></div>
        <div class="stat"><div class="stat-val green">$${revenue.toFixed(2)}</div><div class="stat-label">Revenue</div></div>
        <div class="stat"><div class="stat-val">${contacts.length}</div><div class="stat-label">Contacts</div></div>
      </div>

      <div class="section">
        <div class="section-title">Manual Key Generation</div>
        <form class="gen-form" method="POST" action="/api/keys/manual?pass=${pass}">
          <div><label>Customer Email</label><input type="email" name="email" placeholder="customer@email.com" style="width:240px;"/></div>
          <button type="submit">Generate & Email Key</button>
        </form>
      </div>

      <div class="section">
        <div class="section-title">License Keys</div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Key</th><th>Email</th><th>Status</th><th>Machine</th><th>Activated</th></tr></thead>
            <tbody>${keyRows || `<tr><td colspan="5" style="padding:24px;color:#5a5a6e;text-align:center;">No keys yet.</td></tr>`}</tbody>
          </table>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Contact Messages</div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Subject</th><th>OS</th><th>Message</th><th>Date</th></tr></thead>
            <tbody>${contactRows || `<tr><td colspan="6" style="padding:24px;color:#5a5a6e;text-align:center;">No messages yet.</td></tr>`}</tbody>
          </table>
        </div>
      </div>
    </body>
    </html>
  `);
});

// ── POST /api/keys/manual — generate key from dashboard ──────────────────────
app.post('/api/keys/manual', async (req, res) => {
  const pass  = req.query.pass;
  const email = req.body.email;

  if (pass !== DASHBOARD_PASS) return res.status(401).send('Unauthorized');
  if (!email) return res.redirect(`/dashboard?pass=${pass}`);

  const keys = loadKeys();
  const key  = generateKey();
  keys.push({
    key,
    email,
    orderId:     'manual-' + Date.now(),
    createdAt:   new Date().toISOString(),
    activatedAt: null,
    machine:     null,
    revoked:     false,
    source:      'manual'
  });
  saveKeys(keys);

  // Email key to customer
  try {
    await sendEmail(
      email,
      '🛡 Your Incognito Guard Pro License Key',
      `<div style="font-family:sans-serif;max-width:600px;margin:0 auto;">
        <div style="background:#0a0a0b;padding:24px;border-radius:12px 12px 0 0;">
          <h2 style="color:#ff3e5e;margin:0;">Your Incognito Guard Pro License</h2>
        </div>
        <div style="background:#f9f9f9;padding:32px;border-radius:0 0 12px 12px;">
          <p style="margin-bottom:16px;">Thank you for purchasing Incognito Guard Pro!</p>
          <p>Your license key:</p>
          <div style="background:#0a0a0b;color:#ff3e5e;font-family:monospace;font-size:22px;
            padding:20px;border-radius:8px;margin:16px 0;letter-spacing:0.15em;text-align:center;">
            ${key}
          </div>
          <p style="font-weight:bold;margin-bottom:8px;">How to activate:</p>
          <ol style="margin:8px 0 16px 20px;line-height:2.2;">
            <li>Open Incognito Guard and click <strong>⚙ Settings</strong></li>
            <li>Enter your license key above</li>
            <li>Click <strong>Activate Pro</strong></li>
          </ol>
          <p style="color:#999;font-size:12px;">Need help? Visit incognito-guard.vercel.app/ig-contact.html</p>
        </div>
      </div>`
    );
  } catch (err) {
    console.error('Email failed:', err.message);
  }

  res.redirect(`/dashboard?pass=${pass}`);
});

app.listen(PORT, () => console.log(`Incognito Guard Server running on port ${PORT}`));
