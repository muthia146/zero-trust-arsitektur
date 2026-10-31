const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'db.sqlite'));

db.pragma('foreign_keys = ON');

console.log('Membuat tabel database...');

db.exec(`
  DROP TABLE IF EXISTS audit_log;
  DROP TABLE IF EXISTS transkrip;
  DROP TABLE IF EXISTS nilai;
  DROP TABLE IF EXISTS kelas;
  DROP TABLE IF EXISTS users;

  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'dosen', 'mahasiswa')),
    device_id TEXT NOT NULL
  );

  CREATE TABLE kelas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nama_mata_kuliah TEXT NOT NULL,
    dosen_id INTEGER NOT NULL,
    FOREIGN KEY (dosen_id) REFERENCES users(id)
  );

  CREATE TABLE nilai (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mahasiswa_id INTEGER NOT NULL,
    kelas_id INTEGER NOT NULL,
    nilai_angka REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft', 'final')),
    FOREIGN KEY (mahasiswa_id) REFERENCES users(id),
    FOREIGN KEY (kelas_id) REFERENCES kelas(id)
  );

  CREATE TABLE transkrip (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mahasiswa_id INTEGER NOT NULL,
    kelas_id INTEGER NOT NULL,
    nilai_angka REAL NOT NULL,
    FOREIGN KEY (mahasiswa_id) REFERENCES users(id),
    FOREIGN KEY (kelas_id) REFERENCES kelas(id)
  );

  CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    subject TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    device_id TEXT,
    result TEXT NOT NULL CHECK(result IN ('allow', 'deny')),
    reason TEXT NOT NULL
  );
`);

console.log('Tabel berhasil dibuat. Mengisi seed data...');

const insertUser = db.prepare('INSERT INTO users (username, password, role, device_id) VALUES (?, ?, ?, ?)');

// User Data
const admin = insertUser.run('admin1', 'admin123', 'admin', 'DEV-ADMIN-01');
const dosen1 = insertUser.run('dosen1', 'dosen123', 'dosen', 'DEV-DOSEN-01');
const dosen2 = insertUser.run('dosen2', 'dosen123', 'dosen', 'DEV-DOSEN-02');
const mhs1 = insertUser.run('mhs1', 'mhs123', 'mahasiswa', 'DEV-MHS-01');
const mhs2 = insertUser.run('mhs2', 'mhs123', 'mahasiswa', 'DEV-MHS-02');
const mhs3 = insertUser.run('mhs3', 'mhs123', 'mahasiswa', 'DEV-MHS-03');

// Kelas Data
const insertKelas = db.prepare('INSERT INTO kelas (nama_mata_kuliah, dosen_id) VALUES (?, ?)');
const kelas1 = insertKelas.run('Keamanan Informasi', dosen1.lastInsertRowid);
const kelas2 = insertKelas.run('Pemrograman Web', dosen2.lastInsertRowid);

// Sample Nilai Awal (Status: draft)
const insertNilai = db.prepare('INSERT INTO nilai (mahasiswa_id, kelas_id, nilai_angka, status) VALUES (?, ?, ?, ?)');
insertNilai.run(mhs1.lastInsertRowid, kelas1.lastInsertRowid, 85, 'draft');
insertNilai.run(mhs2.lastInsertRowid, kelas1.lastInsertRowid, 78, 'draft');
insertNilai.run(mhs3.lastInsertRowid, kelas2.lastInsertRowid, 92, 'draft');

console.log('Inisialisasi selesai! File db.sqlite berhasil dibuat.');