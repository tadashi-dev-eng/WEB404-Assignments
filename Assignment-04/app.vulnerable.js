const express = require('express');
const session = require('express-session');
const crypto  = require('crypto');

const app = express();
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: 'sid',
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: false } // VULNERABLE: HttpOnly disabled, no SameSite, no Secure
}));

// Simulate a logged-in user with account state
app.use((req, res, next) => {
  if (!req.session.user) req.session.user = { email: 'tashi@example.com' };
  next();
});

const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));

// VULNERABLE: state-changing endpoint with no CSRF token check
app.get('/account', (req, res) => {
  res.type('html').send(`
    <h1>Account</h1>
    <p>Current email: ${esc(req.session.user.email)}</p>
    <form method="POST" action="/account/email">
      <input name="email" placeholder="new email">
      <button>Change email</button>
    </form>`);
});

app.post('/account/email', (req, res) => {   // no verification!
  req.session.user.email = req.body.email;
  res.send('Email changed to ' + esc(req.body.email));
});

app.listen(3000, () => console.log('VULNERABLE CSRF lab on http://localhost:3000'));
