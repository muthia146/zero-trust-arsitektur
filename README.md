# Sistem Penilaian Akademik - Zero Trust Architecture

Proyek ini adalah implementasi sistem penilaian akademik berbasis _microservices_ yang menerapkan prinsip **Zero Trust Security** sesuai pedoman NIST SP 800-207.

## Ringkasan Arsitektur

Sistem ini terdiri dari tiga komponen utama yang berjalan pada port berbeda:

1. **API Gateway (Port 3000):** Bertindak sebagai _Policy Enforcement Point (PEP)_ dan _Policy Engine (PE)_. Menangani autentikasi JWT, verifikasi perangkat, kontrol akses berbasis atribut (ABAC) dan peran (RBAC), serta mencatat semua aktivitas ke `audit_log`. Meneruskan _request_ valid ke _service_ di belakangnya menggunakan `X-Gateway-Secret`.
2. **Service Nilai (Port 3001):** _Microservice_ pengelola data nilai. Hanya memproses _request_ yang memiliki _Gateway Secret_ dan tidak dapat diakses langsung dari luar.
3. **Service Transkrip (Port 3002):** _Microservice_ pengelola data transkrip. Menerima data sinkronisasi otomatis dari Service Nilai menggunakan _Token Service_ khusus.

## Cara Menjalankan Aplikasi

Pastikan Node.js sudah terinstal. Buka 3 terminal terpisah untuk menjalankan masing-masing _service_:

**Terminal 1 (API Gateway):**
\`\`\`bash
cd api-gateway
npm install
node server.js
\`\`\`

**Terminal 2 (Service Nilai):**
\`\`\`bash
cd service-nilai
npm install
node server.js
\`\`\`

**Terminal 3 (Service Transkrip):**
\`\`\`bash
cd service-transkrip
npm install
node server.js
\`\`\`

## Daftar Akun & Device ID (Data Awal)

Berikut adalah data pengguna bawaan yang dapat digunakan untuk pengujian Postman:

| Role          | Username | Password   | X-Device-ID (Terdaftar) | Keterangan                            |
| ------------- | -------- | ---------- | ----------------------- | ------------------------------------- |
| **Admin**     | `admin1` | `admin123` | `DEV-ADMIN-01`          | Memiliki akses penuh                  |
| **Dosen**     | `dosen1` | `dosen123` | `DEV-DOSEN-01`          | Mengampu Kelas 1 (Keamanan Informasi) |
| **Dosen**     | `dosen2` | `dosen123` | `DEV-DOSEN-02`          | Mengampu Kelas 2 (Pemrograman Web)    |
| **Mahasiswa** | `mhs1`   | `mhs123`   | `DEV-MHS-01`            | Mahasiswa Kelas 1                     |
| **Mahasiswa** | `mhs2`   | `mhs123`   | `DEV-MHS-02`            | Mahasiswa Kelas 1                     |
| **Mahasiswa** | `mhs3`   | `mhs123`   | `DEV-MHS-03`            | Mahasiswa Kelas 2                     |

_Catatan: Semua akses dari pengguna di atas akan dievaluasi oleh Policy Engine. Jika perangkat (X-Device-ID) tidak sesuai atau pengguna mengakses data yang bukan haknya, sistem akan memblokir request (403 Forbidden)._
