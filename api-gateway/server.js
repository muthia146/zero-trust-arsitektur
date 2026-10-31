const express = require('express');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
app.use(express.json());

const PORT = 3000;
const JWT_SECRET = 'SUPER_SECRET_JWT_KEY';
const GATEWAY_SECRET = 'RAHASIA_GATEWAY_123';

const ACCESS_START_HOUR = 7;
const ACCESS_END_HOUR = 21;

const db = new Database(path.join(__dirname, '../database/db.sqlite'));

db.exec(`
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    token TEXT PRIMARY KEY,
    user_id INTEGER
  );
`);

function logAudit(subject, endpoint, deviceId, result, reason) {
  const stmt = db.prepare(`
    INSERT INTO audit_log (subject, endpoint, device_id, result, reason)
    VALUES (?, ?, ?, ?, ?)
  `);
  stmt.run(subject, endpoint, deviceId || 'N/A', result, reason);
}

// ----------------------------------------------------
// 1. ENDPOINT AUTENTIKASI (/auth/*)
// ----------------------------------------------------

app.post('/auth/refresh', (req, res) => {
    const { refresh_token } = req.body;
  
    if (!refresh_token) {
      return res.status(400).json({ error: 'Refresh token wajib diisi!' });
    }
  
    const storedToken = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(refresh_token);
    if (!storedToken) {
      logAudit('UNKNOWN', '/auth/refresh', 'N/A', 'deny', 'Refresh token tidak valid atau sudah dicabut');
      return res.status(403).json({ error: 'Refresh token tidak valid atau telah dicabut!' });
    }
  
    try {
      const decoded = jwt.verify(refresh_token, JWT_SECRET);
      const user = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(decoded.sub);
  
      if (!user) {
        return res.status(404).json({ error: 'User tidak ditemukan!' });
      }
  
      const newAccessToken = jwt.sign(
        { sub: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '10m' }
      );
  
      logAudit(user.username, '/auth/refresh', 'N/A', 'allow', 'Pembaruan access token berhasil');
      res.json({ access_token: newAccessToken, token_type: 'Bearer' });
    } catch (err) {
      logAudit('UNKNOWN', '/auth/refresh', 'N/A', 'deny', 'Refresh token kedaluwarsa');
      return res.status(403).json({ error: 'Refresh token sudah kedaluwarsa!' });
    }
  });

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  const deviceId = req.headers['x-device-id'];

  if (!deviceId) {
    return res.status(400).json({ error: 'Header X-Device-ID wajib disertakan!' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, password);
  if (!user) {
    logAudit(username || 'UNKNOWN', '/auth/login', deviceId, 'deny', 'Kredensial tidak valid');
    return res.status(401).json({ error: 'Username atau password salah!' });
  }

  if (user.device_id !== deviceId) {
    logAudit(user.username, '/auth/login', deviceId, 'deny', 'Perangkat tidak terdaftar untuk user ini');
    return res.status(403).json({ error: 'Akses ditolak: Perangkat tidak terdaftar!' });
  }

  const accessToken = jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '10m' }
  );

  const refreshToken = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '1d' });
  db.prepare('INSERT INTO refresh_tokens (token, user_id) VALUES (?, ?)').run(refreshToken, user.id);

  logAudit(user.username, '/auth/login', deviceId, 'allow', 'Login berhasil');

  res.json({
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: 'Bearer'
  });
});

app.post('/auth/service', (req, res) => {
  const { clientId, clientSecret } = req.body;

  if (clientId === 'service-nilai' && clientSecret === 'SECRET-SERVICE-NILAI-999') {
    const serviceToken = jwt.sign(
      { sub: 'service-nilai', role: 'service' },
      JWT_SECRET,
      { expiresIn: '5m' } 
    );

    logAudit('service-nilai', '/auth/service', 'INTERNAL', 'allow', 'Penerbitan token service berhasil');
    return res.json({ access_token: serviceToken });
  }

  logAudit('UNKNOWN_SERVICE', '/auth/service', 'INTERNAL', 'deny', 'Kredensial service tidak valid');
  res.status(401).json({ error: 'Client ID atau Secret Service salah!' });
});

// POST /auth/logout
app.post('/auth/logout', (req, res) => {
  const { refresh_token } = req.body;
  if (refresh_token) {
    db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refresh_token);
  }
  res.json({ message: 'Logout berhasil, refresh token dicabut.' });
});

// ----------------------------------------------------
// 2. POLICY ENGINE MIDDLEWARE (ABAC & RBAC)
// ----------------------------------------------------
const policyEngine = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const deviceId = req.headers['x-device-id'];
  const endpoint = req.originalUrl;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logAudit('ANONYMOUS', endpoint, deviceId, 'deny', 'Token Authorization tidak ditemukan');
    return res.status(401).json({ error: 'Token Authorization diperlukan!' });
  }

  const token = authHeader.split(' ')[1];
  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
  } catch (err) {
    logAudit('ANONYMOUS', endpoint, deviceId, 'deny', 'Token tidak valid atau kedaluwarsa');
    return res.status(401).json({ error: 'Token tidak valid atau kedaluwarsa!' });
  }

  const subject = decoded.username || decoded.sub;

  if (decoded.role !== 'service') {
    if (!deviceId) {
      logAudit(subject, endpoint, deviceId, 'deny', 'Header X-Device-ID tidak ditemukan');
      return res.status(400).json({ error: 'Header X-Device-ID diperlukan!' });
    }

    const userInDb = db.prepare('SELECT device_id FROM users WHERE id = ?').get(decoded.sub);
    if (!userInDb || userInDb.device_id !== deviceId) {
      logAudit(subject, endpoint, deviceId, 'deny', 'Device ID tidak cocok dengan pendaftaran user');
      return res.status(403).json({ error: 'Akses ditolak: Perangkat tidak terdaftar!' });
    }
  }

  const currentHour = new Date().getHours();

  if (req.method === 'PUT' && endpoint.startsWith('/nilai/')) {
    const nilaiId = req.params.id || endpoint.split('/')[2];

    if (decoded.role !== 'dosen') {
      logAudit(subject, endpoint, deviceId, 'deny', 'Hanya Dosen yang dapat mengubah nilai');
      return res.status(403).json({ error: 'Akses ditolak: Role bukan Dosen!' });
    }

    if (currentHour < ACCESS_START_HOUR || currentHour >= ACCESS_END_HOUR) {
      logAudit(subject, endpoint, deviceId, 'deny', 'Akses di luar jam kerja (07.00-21.00)');
      return res.status(403).json({ error: 'Akses ditolak: Perubahan nilai hanya diizinkan pukul 07.00-21.00!' });
    }

    const dataNilai = db.prepare(`
      SELECT n.status, k.dosen_id 
      FROM nilai n 
      JOIN kelas k ON n.kelas_id = k.id 
      WHERE n.id = ?
    `).get(nilaiId);

    if (!dataNilai) {
      logAudit(subject, endpoint, deviceId, 'deny', 'Data nilai tidak ditemukan');
      return res.status(404).json({ error: 'Data nilai tidak ditemukan!' });
    }

    if (dataNilai.dosen_id !== decoded.sub) {
      logAudit(subject, endpoint, deviceId, 'deny', 'Dosen tidak mengampu kelas ini');
      return res.status(403).json({ error: 'Akses ditolak: Anda tidak mengampu kelas ini!' });
    }

    if (dataNilai.status === 'final') {
      logAudit(subject, endpoint, deviceId, 'deny', 'Nilai sudah berstatus final');
      return res.status(400).json({ error: 'Nilai sudah final dan tidak dapat diubah!' });
    }
  }

  if (req.method === 'POST' && endpoint.includes('/finalisasi')) {
    if (decoded.role !== 'dosen') {
      logAudit(subject, endpoint, deviceId, 'deny', 'Hanya Dosen yang dapat memfinalisasi nilai');
      return res.status(403).json({ error: 'Akses ditolak!' });
    }

    if (currentHour < ACCESS_START_HOUR || currentHour >= ACCESS_END_HOUR) {
      logAudit(subject, endpoint, deviceId, 'deny', 'Finalisasi di luar jam kerja');
      return res.status(403).json({ error: 'Akses ditolak: Finalisasi hanya diizinkan pukul 07.00-21.00!' });
    }
  }

  if (req.method === 'GET' && endpoint.startsWith('/transkrip/')) {
    const targetNim = endpoint.split('/')[2];
    if (decoded.role === 'mahasiswa' && decoded.username !== targetNim) {
      logAudit(subject, endpoint, deviceId, 'deny', 'Mahasiswa mencoba melihat transkrip milik orang lain');
      return res.status(403).json({ error: 'Akses ditolak: Anda hanya dapat melihat transkrip sendiri!' });
    }
  }

  if (endpoint === '/transkrip/sinkron') {
    if (decoded.role !== 'service') {
      logAudit(subject, endpoint, deviceId, 'deny', 'Endpoint sinkronisasi hanya untuk token service');
      return res.status(403).json({ error: 'Akses ditolak: User tidak diizinkan memanggil sinkronisasi!' });
    }
  }

  logAudit(subject, endpoint, deviceId, 'allow', 'Otorisasi berhasil');
  next();
};


// Helper untuk menyuntikkan Secret & meneruskan body JSON lewat proxy
const fixProxyBody = (proxyReq, req) => {
  proxyReq.setHeader('X-Gateway-Secret', GATEWAY_SECRET);
  if (req.body && Object.keys(req.body).length > 0) {
    const bodyData = JSON.stringify(req.body);
    proxyReq.setHeader('Content-Type', 'application/json');
    proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
    proxyReq.write(bodyData);
  }
};

// Proxy ke Service Nilai (Port 3001)
app.use(['/nilai', '/kelas'], policyEngine, createProxyMiddleware({
  target: 'http://localhost:3001',
  changeOrigin: true,
  pathRewrite: (path, req) => req.originalUrl,
  on: {
    proxyReq: fixProxyBody
  }
}));

// Proxy ke Service Transkrip (Port 3002)
app.use('/transkrip', policyEngine, createProxyMiddleware({
  target: 'http://localhost:3002',
  changeOrigin: true,
  pathRewrite: (path, req) => req.originalUrl,
  on: {
    proxyReq: fixProxyBody
  }
}));

app.listen(PORT, () => {
  console.log(`API Gateway (PEP/PE) berjalan di http://localhost:${PORT}`);
});