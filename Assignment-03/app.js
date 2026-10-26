const express = require('express');
const multer  = require('multer');
const crypto  = require('crypto');
const path    = require('path');
const fs      = require('fs');
const net     = require('net');
const { execFile } = require('child_process');

const app = express();
app.use(express.static('public'));

// ---- SECURE command execution: execFile(), array args, strict IP allowlist, no shell ----
app.get('/ping', (req, res) => {
  const host = String(req.query.host || '');
  if (net.isIP(host) === 0) {
    return res.status(400).type('text/plain').send('Invalid host.');
  }
  execFile('ping', ['-c', '1', '--', host], { timeout: 5000 },
    (err, stdout, stderr) => res.type('text/plain').send(stdout || stderr || 'ping failed'));
});

// ---- SECURE file upload ----
const UPLOAD_DIR = path.join(__dirname, 'storage', 'uploads'); // OUTSIDE public/
const TMP_DIR    = path.join(__dirname, 'storage', 'tmp');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });

const ALLOWED_EXT  = new Set(['.png', '.jpg', '.jpeg', '.pdf']);
const ALLOWED_MIME = new Set(['image/png', 'image/jpeg', 'application/pdf']);

const upload = multer({
  dest: TMP_DIR,
  limits: { fileSize: 5 * 1024 * 1024, files: 1 }   // Layer 1: 5 MB cap, one file
});

// Layer 4: verify the REAL type from magic bytes (never trust extension/MIME)
async function sniffType(filePath) {
  const fd = await fs.promises.open(filePath, 'r');
  const { buffer } = await fd.read({ buffer: Buffer.alloc(8), position: 0 });
  await fd.close();
  if (buffer.slice(0, 8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a])))
    return { ext: 'png', mime: 'image/png' };
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF)
    return { ext: 'jpg', mime: 'image/jpeg' };
  if (buffer.slice(0, 4).toString() === '%PDF')
    return { ext: 'pdf', mime: 'application/pdf' };
  return null;
}

app.post('/upload', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file');
  const tmpPath = req.file.path;
  try {
    const ext = path.extname(req.file.originalname).toLowerCase();
    if (!ALLOWED_EXT.has(ext))                 throw new Error('extension not allowed');      // Layer 2
    if (!ALLOWED_MIME.has(req.file.mimetype))  throw new Error('declared type not allowed');  // Layer 3

    const real = await sniffType(tmpPath);                                                    // Layer 4
    if (!real || !ALLOWED_MIME.has(real.mime)) throw new Error('content is not an allowed type');

    const safeName = crypto.randomUUID() + '.' + real.ext;                                    // Layer 5: UUID rename
    const destPath = path.join(UPLOAD_DIR, safeName);                                         // Layer 6: outside web root
    await fs.promises.rename(tmpPath, destPath);
    await fs.promises.chmod(destPath, 0o640);                                                 // Layer 7: no execute bit

    res.send('Stored safely as ' + safeName);
  } catch (e) {
    fs.promises.unlink(tmpPath).catch(() => {});
    res.status(400).send('Rejected: ' + e.message);
  }
});

app.listen(3000, () => console.log('SECURE lab on http://localhost:3000'));