const express = require('express');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
app.use(express.json());

const PORT = 3001;
const JWT_SECRET = 'SUPER_SECRET_JWT_KEY';
const GATEWAY_SECRET = 'RAHASIA_GATEWAY_123';

const db = new Database(path.join(__dirname, '../database/db.sqlite'));

// Middleware Defense in Depth[cite: 2]
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

// Endpoint GET /nilai[cite: 2]
// Endpoint GET /nilai (Filtered by Role)[cite: 2, 3]
app.get('/nilai', (req, res) => {
    const { sub, role } = req.user; // Diambil otomatis dari payload JWT oleh middleware verifyServiceAuth
  
    let baseQuery = `
      SELECT n.id, u.username AS mahasiswa, k.nama_mata_kuliah, n.nilai_angka, n.status
      FROM nilai n
      JOIN users u ON n.mahasiswa_id = u.id
      JOIN kelas k ON n.kelas_id = k.id
    `;
  
    let results = [];
  
    if (role === 'mahasiswa') {
      // Mahasiswa hanya melihat nilai miliknya sendiri[cite: 2, 3]
      results = db.prepare(`${baseQuery} WHERE n.mahasiswa_id = ?`).all(sub);
    } else if (role === 'dosen') {
      // Dosen hanya melihat nilai pada kelas yang diampunya[cite: 2, 3]
      results = db.prepare(`${baseQuery} WHERE k.dosen_id = ?`).all(sub);
    } else if (role === 'admin') {
      // Admin dapat melihat seluruh nilai
      results = db.prepare(baseQuery).all();
    } else {
      return res.status(403).json({ error: 'Akses ditolak: Role tidak valid!' });
    }
  
    res.json({ status: 'success', data: results });
  });

// Endpoint PUT /nilai/:id[cite: 2]
app.put('/nilai/:id', (req, res) => {
  const { id } = req.params;
  const { nilai_angka } = req.body;

  const updateStmt = db.prepare('UPDATE nilai SET nilai_angka = ? WHERE id = ?');
  const result = updateStmt.run(nilai_angka, id);

  if (result.changes === 0) {
    return res.status(404).json({ error: 'Data nilai tidak ditemukan!' });
  }

  res.json({ status: 'success', message: 'Nilai berhasil diperbarui!' });
});

// Endpoint POST /kelas/:id/finalisasi (Otomatis Ambil Service Token)
app.post('/kelas/:id/finalisasi', async (req, res) => {
  const { id } = req.params;

  try {
    // 1. Service Nilai otomatis meminta Token Service ke Gateway[cite: 2]
    const authRes = await fetch('http://localhost:3000/auth/service', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        clientId: 'service-nilai',
        clientSecret: 'SECRET-SERVICE-NILAI-999'
      })
    });

    const authData = await authRes.json();
    if (!authRes.ok) {
      return res.status(500).json({ error: 'Gagal mendapatkan token service', detail: authData });
    }

    const serviceToken = authData.access_token;

    // 2. Ubah status nilai menjadi final di database
    const updateStmt = db.prepare("UPDATE nilai SET status = 'final' WHERE kelas_id = ?");
    updateStmt.run(id);

    // 3. Ambil data nilai yang baru difinalisasi
    const getNilaiStmt = db.prepare('SELECT mahasiswa_id, kelas_id, nilai_angka FROM nilai WHERE kelas_id = ?');
    const items = getNilaiStmt.all(id);

    // 4. Panggil Service Transkrip melalui Gateway menggunakan Token Service
    const response = await fetch('http://localhost:3000/transkrip/sinkron', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`
      },
      body: JSON.stringify({ items })
    });

    const result = await response.json();
    if (!response.ok) {
      return res.status(response.status).json({ error: 'Gagal sinkronisasi transkrip', detail: result });
    }

    res.json({ status: 'success', message: 'Kelas berhasil difinalisasi dan disinkronkan ke transkrip!' });
  } catch (err) {
    res.status(500).json({ error: 'Gagal menghubungi gateway untuk sinkronisasi transkrip', details: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Service Nilai berjalan di http://localhost:${PORT}`);
});