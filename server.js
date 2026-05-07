const express    = require('express');
const nodemailer = require('nodemailer');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Config ────────────────────────────────────────────────────────────────────
const GMAIL_USER        = process.env.GMAIL_USER        || '';
const GMAIL_PASS        = process.env.GMAIL_PASS        || '';
const NOTIFY_EMAIL      = process.env.NOTIFY_EMAIL      || '';
const DASHBOARD_PASS    = process.env.DASHBOARD_PASS    || 'ig2024';
const LS_WEBHOOK_SECRET = process.env.LS_WEBHOOK_SECRET || '';

// Pro download links (update these when you publish new releases)
const PRO_DOWNLOADS = {
  windows: 'https://incognito-guard.vercel.app/ig-pro-download.html',
  linux:   'https://incognito-guard.vercel.app/ig-pro-download.html',
  macos:   'https://incognito-guard.vercel.app/ig-pro-download.html',
};

// ── Data files ────────────────────────────────────────────────────────────────
const DATA_DIR      = path.join(__dirname, 'data');
const CONTACTS_FILE = path.join(DATA_DIR, 'contacts.json');
const ORDERS_FILE   = path.join(DATA_DIR, 'orders.json');

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(CONTACTS_FILE)) fs.writeFileSync(CONTACTS_FILE, '[]');
if (!fs.existsSync(ORDERS_FILE))   fs.writeFileSync(ORDERS_FILE,   '[]');

// ── Middleware ────────────────────────────────────────────────────────────────
app.use('/api/lemonsqueezy/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
    to, subject, html
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

function loadOrders() {
  try { return JSON.parse(fs.readFileSync(ORDERS_FILE, 'utf8')); }
  catch (_) { return []; }
}
function saveOrders(data) {
  fs.writeFileSync(ORDERS_FILE, JSON.stringify(data, null, 2));
}

// ── Health check ──────────────────────────────────────────────────────────────
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
      id: crypto.randomUUID(),
      name, email, subject, os, message,
      receivedAt: new Date().toISOString()
    };

    const contacts = loadContacts();
    contacts.unshift(entry);
    saveContacts(contacts);

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

    // Prevent duplicate emails
    const orders   = loadOrders();
    const existing = orders.find(o => o.orderId === orderId);
    if (existing) {
      console.log('Order already processed:', orderId);
      return res.json({ received: true, note: 'Already processed' });
    }

    // Save order
    orders.push({
      orderId,
      email,
      processedAt: new Date().toISOString()
    });
    saveOrders(orders);

    // Email Pro download links to customer
    await sendEmail(
      email,
      '🛡 Your Incognito Guard Pro Download',
      `<div style="font-family:sans-serif;max-width:600px;margin:0 auto;">
        <div style="background:#0a0a0b;padding:24px;border-radius:12px 12px 0 0;">
          <h2 style="color:#ff3e5e;margin:0;">🛡 Incognito Guard Pro</h2>
          <p style="color:#ffcdd2;margin:4px 0 0;">Thank you for your purchase!</p>
        </div>
        <div style="background:#f9f9f9;padding:32px;border-radius:0 0 12px 12px;">
          <p style="margin-bottom:20px;font-size:15px;">
            Your Pro download is ready. Choose your operating system:
          </p>

          <div style="text-align:center;margin-bottom:24px;">
            <a href="https://incognito-guard.vercel.app/ig-pro-download.html"
               style="display:inline-block;background:#ff3e5e;color:#fff;
               font-family:monospace;font-size:16px;font-weight:bold;
               padding:16px 40px;border-radius:8px;text-decoration:none;">
              ⬇ Download Incognito Guard Pro
            </a>
            <p style="margin-top:8px;font-size:12px;color:#999;">
              Windows · Linux · macOS — all included
            </p>
          </div>

          <div style="background:#fff8f8;border:1px solid #ffcdd2;border-radius:8px;padding:16px;margin-bottom:20px;">
            <p style="margin:0;font-size:13px;color:#555;">
              <strong>Quick setup:</strong><br/>
              1. Extract the zip to your Desktop<br/>
              2. Fill in your email in <code>config.json</code><br/>
              3. Run <code>install.ps1</code> (Windows) or <code>install.sh</code> (Linux/macOS) as Admin<br/>
              4. Open IncognitoGuard — email alerts are ready!
            </p>
          </div>

          <p style="color:#999;font-size:12px;">
            Order ID: ${orderId}<br/>
            Need help? Visit
            <a href="https://incognito-guard.vercel.app/ig-contact.html">incognito-guard.vercel.app</a>
            or reply to this email.
          </p>
          <p style="color:#ccc;font-size:11px;margin-top:16px;">
            Built for parents who care. — Incognito Guard
          </p>
        </div>
      </div>`
    );

    // Notify owner
    await notifyOwner(
      `💰 New Incognito Guard Sale — $19.99 from ${email}`,
      `<div style="font-family:sans-serif;max-width:500px;">
        <div style="background:#0a0a0b;padding:20px;border-radius:12px 12px 0 0;">
          <h2 style="color:#ff3e5e;margin:0;">New Sale! 🎉</h2>
        </div>
        <div style="background:#f9f9f9;padding:20px;border-radius:0 0 12px 12px;">
          <p><strong>Customer:</strong> ${email}</p>
          <p><strong>Order ID:</strong> ${orderId}</p>
          <p><strong>Date:</strong> ${new Date().toISOString()}</p>
          <p><strong>Download links sent ✓</strong></p>
        </div>
      </div>`
    );

    console.log(`Pro download links sent to ${email}`);
    res.json({ success: true });

  } catch (err) {
    console.error('LS webhook error:', err.message);
    res.status(500).json({ error: err.message });
  }
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
  const orders   = loadOrders();

  const orderRows = orders.slice().reverse().map(o => `
    <tr style="border-bottom:1px solid #252529;">
      <td style="padding:10px;font-size:12px;color:#ff3e5e;">${o.orderId}</td>
      <td style="padding:10px;font-size:12px;"><a href="mailto:${o.email}" style="color:#38b6ff;">${o.email}</a></td>
      <td style="padding:10px;font-size:11px;color:#00e5a0;">✓ Sent</td>
      <td style="padding:10px;font-size:11px;color:#5a5a6e;">${o.processedAt?.slice(0,10)}</td>
    </tr>
  `).join('');

  const contactRows = contacts.map(c => `
    <tr style="border-bottom:1px solid #252529;">
      <td style="padding:10px;font-size:13px;">${c.name}</td>
      <td style="padding:10px;"><a href="mailto:${c.email}" style="color:#38b6ff;font-size:12px;">${c.email}</a></td>
      <td style="padding:10px;font-size:12px;color:#5a5a6e;">${c.subject}</td>
      <td style="padding:10px;font-size:11px;color:#5a5a6e;">${c.os || '—'}</td>
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
        .table-wrap{overflow-x:auto;}
        table{width:100%;border-collapse:collapse;background:#16161a;border:1px solid #252529;border-radius:12px;overflow:hidden;}
        th{padding:12px;text-align:left;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;color:#5a5a6e;border-bottom:1px solid #252529;}
      </style>
    </head>
    <body>
      <div class="header">
        <div class="logo">🛡 INCOGNITO<span>GUARD</span> Dashboard</div>
        <div style="font-size:12px;color:#5a5a6e;">${new Date().toLocaleDateString()}</div>
      </div>

      <div class="stats">
        <div class="stat"><div class="stat-val green">${orders.length}</div><div class="stat-label">Total Sales</div></div>
        <div class="stat"><div class="stat-val green">$${(orders.length * 19.99).toFixed(2)}</div><div class="stat-label">Revenue</div></div>
        <div class="stat"><div class="stat-val">${contacts.length}</div><div class="stat-label">Contacts</div></div>
      </div>

      <div class="section">
        <div class="section-title">Orders — Pro Download Sent</div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Order ID</th><th>Email</th><th>Status</th><th>Date</th></tr></thead>
            <tbody>${orderRows || `<tr><td colspan="4" style="padding:24px;color:#5a5a6e;text-align:center;">No orders yet.</td></tr>`}</tbody>
          </table>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Contact Messages</div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Subject</th><th>OS</th><th>Date</th></tr></thead>
            <tbody>${contactRows || `<tr><td colspan="5" style="padding:24px;color:#5a5a6e;text-align:center;">No messages yet.</td></tr>`}</tbody>
          </table>
        </div>
      </div>
    </body>
    </html>
  `);
});

app.listen(PORT, () => console.log(`Incognito Guard Server running on port ${PORT}`));
