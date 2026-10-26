const express = require('express');
const multer  = require('multer');
const { exec } = require('child_process');

const app = express();
app.use(express.static('public'));

// --- VULNERABLE command execution: exec() runs a shell on a concatenated string ---
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    res.type('text/plain').send(stdout || stderr || String(err));
  });
});

// --- VULNERABLE file upload: keeps the attacker's filename, stores in the web root ---
const vulnStorage = multer.diskStorage({
  destination: 'public/uploads/',
  filename: (req, file, cb) => cb(null, file.originalname) // attacker controls name + extension
});
const uploadVuln = multer({ storage: vulnStorage });

app.post('/upload', uploadVuln.single('file'), (req, res) => {
  res.send('Uploaded: /uploads/' + req.file.originalname);
});

app.listen(3000, () => console.log('VULNERABLE lab on http://localhost:3000'));