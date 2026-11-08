// Builds invalid tokens for local verification tests against this lab's own app.
// usage: node make-token.js <expired|wrong-issuer|wrong-audience|wrong-key|tampered|none|hs256>
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'keys/private.pem'));
const PUBLIC_KEY  = fs.readFileSync(path.join(__dirname, 'keys/public.pem'));

const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const now = Math.floor(Date.now() / 1000);
const claims = { sub: 'user-1001', role: 'admin', iss: 'web404-auth', aud: 'web404-api', iat: now, exp: now + 900 };
const sign = (payload, key = PRIVATE_KEY) => jwt.sign(payload, key, { algorithm: 'RS256' });

const kinds = {
  expired: () => sign({ ...claims, iat: now - 1800, exp: now - 900 }),
  'wrong-issuer': () => sign({ ...claims, iss: 'someone-else' }),
  'wrong-audience': () => sign({ ...claims, aud: 'another-api' }),
  'wrong-key': () => sign(claims, crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey),
  tampered: () => {
    const [header, , signature] = sign({ ...claims, role: 'user' }).split('.');
    return `${header}.${b64(claims)}.${signature}`;
  },
  none: () => `${b64({ alg: 'none', typ: 'JWT' })}.${b64(claims)}.`,
  hs256: () => {
    const body = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(claims)}`;
    return `${body}.${crypto.createHmac('sha256', PUBLIC_KEY).update(body).digest('base64url')}`;
  }
};

const build = kinds[process.argv[2]];
if (!build) {
  console.error(`usage: node make-token.js <${Object.keys(kinds).join('|')}>`);
  process.exit(1);
}
console.log(build());
