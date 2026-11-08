// Serves the attacker page on port 4000, separate from the app on port 3000.
//   node attacker-server.js          -> http,  attacker.html (vulnerable app)
//   node attacker-server.js --https  -> https, attacker.secure.html (secure app)
const fs    = require('fs');
const http  = require('http');
const https = require('https');
const path  = require('path');

const useTls = process.argv.includes('--https');
const page = fs.readFileSync(path.join(__dirname, useTls ? 'attacker.secure.html' : 'attacker.html'));

const handler = (req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(page);
};

const server = useTls
  ? https.createServer({
      key:  fs.readFileSync(path.join(__dirname, 'certs', 'localhost.key')),
      cert: fs.readFileSync(path.join(__dirname, 'certs', 'localhost.crt'))
    }, handler)
  : http.createServer(handler);

server.listen(4000, () => console.log(`Attacker page on ${useTls ? 'https' : 'http'}://localhost:4000/attacker.html`));
