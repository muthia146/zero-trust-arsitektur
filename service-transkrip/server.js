const express = require('express');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
app.use(express.json());

const PORT = 3002;
const JWT_SECRET = 'SUPER_SECRET_JWT_KEY';
const GATEWAY_SECRET = 'RAHASIA_GATEWAY_123';

const db = new Database(path.join(__dirname, '../database/db.sqlite'));

const verifyServiceAuth = (req, res, next) => {
  const gatewaySecretHeader = req.headers['x-gateway-secret'];

  if (!gatewaySecretHeader || gatewaySecretHeader !== GATEWAY_SECRET) {
    return res.status(403).json({ error: 'Akses ditolak: Request harus melalui API Gateway!' });
  }

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token tidak ditemukan!' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; 
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token tidak valid atau sudah kedaluwarsa!' });
  }
};

app.use(verifyServiceAuth);

app.get('/transkrip/:nim', (req, res) => {
  const { nim } = req.params;

  const query = db.prepare(`
    SELECT t.id, u.username AS nim, k.nama_mata_kuliah, t.nilai_angka
    FROM transkrip t
    JOIN users u ON t.mahasiswa_id = u.id
    JOIN kelas k ON t.kelas_id = k.id
    WHERE u.username = ?
  `);

  const results = query.all(nim);
  res.json({ status: 'success', data: results });
});

app.post('/transkrip/sinkron', (req, res) => {

  if (req.user.role !== 'service') {
    return res.status(403).json({ error: 'Akses ditolak: Endpoint ini hanya untuk antar-service!' });
  }

  const { items } = req.body; 

  if (!items || !Array.isArray(items)) {
    return res.status(400).json({ error: 'Format data tidak valid!' });
  }

  const insertStmt = db.prepare(`
    INSERT INTO transkrip (mahasiswa_id, kelas_id, nilai_angka)
    VALUES (?, ?, ?)
  `);

  const transaction = db.transaction((dataList) => {
    for (const item of dataList) {
      insertStmt.run(item.mahasiswa_id, item.kelas_id, item.nilai_angka);
    }
  });

  transaction(items);

  res.json({ status: 'success', message: 'Sinkronisasi transkrip berhasil!' });
});

app.listen(PORT, () => {
  console.log(`Service Transkrip berjalan di http://localhost:${PORT}`);
});