const express      = require('express');
const cookieParser = require('cookie-parser');
const jwt          = require('jsonwebtoken');
const crypto       = require('crypto');
const fs           = require('fs');
const https        = require('https');
const path         = require('path');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);
const read = file => fs.readFileSync(path.join(__dirname, file));

const PRIVATE_KEY = read('keys/private.pem');
const PUBLIC_KEY  = read('keys/public.pem');

const ISSUER   = 'web404-auth';
const AUDIENCE = 'web404-api';
const TOKEN_LIFETIME_SECONDS = 15 * 60;

const COOKIE_OPTIONS = {
  httpOnly: true,       // page scripts cannot read the token, which limits XSS theft
  secure: true,         // only sent over HTTPS
  sameSite: 'strict',   // not attached to cross-site requests
  path: '/'
};

// Lab fixture: one user, with the password stored only as a salted scrypt hash
const DEMO_PASSWORD = process.env.DEMO_PASSWORD || 'lab-password-only';
const salt = crypto.randomBytes(16);
const users = new Map([
  ['tashi', { id: 'user-1001', role: 'user', hash: crypto.scryptSync(DEMO_PASSWORD, salt, 64) }]
]);
const dummyHash = crypto.scryptSync(crypto.randomBytes(16), salt, 64);

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// SECURE TOKEN ISSUANCE: minimal claims, RS256, short lifetime
function issueToken(user) {
  return jwt.sign({ role: user.role }, PRIVATE_KEY, {
    algorithm: 'RS256',
    subject: user.id,
    issuer: ISSUER,
    audience: AUDIENCE,
    expiresIn: TOKEN_LIFETIME_SECONDS
  });
}

// SECURE VERIFICATION MIDDLEWARE: fixed algorithm, signature, exp, iss and aud
function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.sendStatus(401);

  jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],
    issuer: ISSUER,
    audience: AUDIENCE
  }, (err, claims) => {
    if (err) {
      console.warn(`[JWT] rejected ${req.method} ${req.originalUrl}: ${err.message}`);
      return res.sendStatus(403);
    }
    req.user = claims;
    next();
  });
}

const requireRole = role => (req, res, next) =>
  req.user.role === role ? next() : res.sendStatus(403);

app.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body ?? {};
    if (typeof username !== 'string' || typeof password !== 'string') return res.sendStatus(400);

    const user = users.get(username);
    // Hash even for unknown users, so response time does not reveal valid usernames
    const actual = await scrypt(password, salt, 64);
    const valid = crypto.timingSafeEqual(actual, user ? user.hash : dummyHash) && Boolean(user);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    res.cookie('token', issueToken(user), { ...COOKIE_OPTIONS, maxAge: TOKEN_LIFETIME_SECONDS * 1000 });
    res.json({ message: 'Logged in' });
  } catch (err) {
    next(err);
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('token', COOKIE_OPTIONS);
  res.sendStatus(204);
});

app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({ sub: req.user.sub, role: req.user.role });
});

app.get('/api/admin', authenticateToken, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin area' });
});

const tls = { key: read('certs/localhost.key'), cert: read('certs/localhost.crt') };

https.createServer(tls, app).listen(3000, () =>
  console.log('Secure JWT lab on https://localhost:3000'));
