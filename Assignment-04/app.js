const express = require('express');
const session = require('express-session');
const crypto  = require('crypto');
const fs      = require('fs');
const https   = require('https');
const path    = require('path');

const app = express();
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: 'sid',
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,       // page scripts cannot read the cookie
    secure: true,         // only sent over HTTPS
    sameSite: 'strict'    // not attached to cross-site requests
  }
}));

// Simulate a logged-in user with account state
app.use((req, res, next) => {
  if (!req.session.user) req.session.user = { email: 'tashi@example.com' };
  next();
});

const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));

// Synchronizer Token Pattern: one random token per session, stored server-side
function getCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

function tokensMatch(sent, expected) {
  if (typeof sent !== 'string' || typeof expected !== 'string') return false;
  const a = Buffer.from(sent);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Runs before every route, so POST, PUT, DELETE and PATCH are all covered
function verifyCsrf(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  const sent = req.body?._csrf ?? req.get('x-csrf-token');
  if (tokensMatch(sent, req.session.csrfToken)) return next();

  console.warn(`[CSRF] blocked ${req.method} ${req.originalUrl} origin=${req.get('origin') || 'none'}`);
  res.status(403).type('text').send('Forbidden: invalid or missing CSRF token');
}

app.use(verifyCsrf);

app.get('/account', (req, res) => {
  res.type('html').send(`
    <h1>Account</h1>
    <p>Current email: ${esc(req.session.user.email)}</p>
    <form method="POST" action="/account/email">
      <input type="hidden" name="_csrf" value="${esc(getCsrfToken(req))}">
      <input name="email" placeholder="new email">
      <button>Change email</button>
    </form>`);
});

function changeEmail(req, res) {
  const email = req.body?.email;
  if (typeof email !== 'string' || email === '') return res.status(400).send('Email is required');
  req.session.user.email = email;
  res.send('Email changed to ' + esc(email));
}

app.post('/account/email', changeEmail);
app.put('/account/email', changeEmail);

app.delete('/account/email', (req, res) => {
  req.session.user.email = 'tashi@example.com';
  res.send('Email reset to default');
});

// Secure cookies need HTTPS, so the lab uses a local self-signed certificate
const tls = {
  key:  fs.readFileSync(path.join(__dirname, 'certs', 'localhost.key')),
  cert: fs.readFileSync(path.join(__dirname, 'certs', 'localhost.crt'))
};

https.createServer(tls, app).listen(3000, () =>
  console.log('SECURE CSRF lab on https://localhost:3000'));
