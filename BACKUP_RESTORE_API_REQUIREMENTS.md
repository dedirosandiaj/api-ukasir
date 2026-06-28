# Persyaratan API: Migrasi Backup & Restore S3 Menggunakan Pre-Signed URL

## 1. Latar Belakang
Saat ini aplikasi mobile **uKasir** melakukan komunikasi, otentikasi (AWS Signature V4), dan upload/download secara langsung ke server MinIO/S3 dari sisi klien. Hal ini mengharuskan `Access Key` dan `Secret Key` tertanam secara permanen (*hardcode*) di dalam *source code* aplikasi. 

Dari sisi keamanan (*cybersecurity*), ini sangat berisiko karena *Secret Key* dapat diretas melalui teknik *reverse engineering*. Jika bocor, peretas berpotensi mengambil alih atau menghapus data milik *merchant/tenant* lain.

## 2. Tujuan Migrasi
- **Memusatkan Keamanan:** Memindahkan `Secret Key` MinIO/S3 murni hanya di sisi Backend (Server). Aplikasi mobile tidak akan pernah mengetahui kredensial server S3.
- **Pre-Signed URL:** Backend akan bertindak sebagai "Pemberi Izin Sementara". Jika aplikasi mobile ingin meng-upload atau men-download file, aplikasi akan meminta izin ke Backend. Backend kemudian merespons dengan memberikan URL rahasia S3 sekali pakai (*Pre-signed URL*) yang hanya valid untuk durasi tertentu (misalnya 10 menit).
- **Penyesuaian Minimal di Mobile:** Aplikasi mobile hanya tinggal melakukan standard HTTP `PUT` ke URL yang diberikan untuk upload, dan HTTP `GET` untuk download.

---

## 3. Desain & Kontrak API (API Requirements)

Backend diharapkan membuat **4 Endpoint Utama** yang dilindungi oleh otentikasi standar yang sudah ada (misalnya menggunakan *Bearer Token* dari pengguna yang sedang login).

Semua letak folder/path objek di dalam S3 harus diatur secara absolut oleh Backend berdasarkan Token/ID Merchant pengguna yang bersangkutan untuk menghindari *Unauthorized Cross-Tenant Access* (misalnya: `ukasir/{merchant_token}/nama_file.sql`).

### A. Endpoint List Backups
Mengambil daftar file backup (*database*) yang dimiliki oleh merchant yang sedang login.

- **URL:** `GET /api/v1/backups`
- **Headers:** `Authorization: Bearer <user_token>`
- **Deskripsi Backend:** Backend menggunakan S3 SDK (`listObjects`) untuk mengambil daftar file berakhiran `.sql` atau `.db` di dalam folder milik merchant tersebut.
- **Expected Response (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "file_name": "7077601022884802_2026-06-28_142030.sql",
      "date": "2026-06-28",
      "time": "14:20 WIB",
      "size": "450.5KB"
    }
  ]
}
```

### B. Endpoint Generate Upload URL (Pre-Signed PUT)
Meminta URL sementara untuk mengunggah (upload) file backup baru.

- **URL:** `POST /api/v1/backups/upload-url`
- **Headers:** `Authorization: Bearer <user_token>`
- **Request Body:**
```json
{
  "file_name": "7077601022884802_2026-06-28_142030.sql",
  "content_type": "application/octet-stream"
}
```
- **Deskripsi Backend:** Backend memvalidasi request, lalu men-generate **Pre-Signed URL** khusus untuk operasi HTTP `PUT` (durasi kedaluwarsa disarankan 10 menit).
- **Expected Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "upload_url": "https://s3.ucentric.id/ukasir/7077601022884802/7077601022884802_2026-06-28_142030.sql?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...&X-Amz-Signature=..."
  }
}
```
> **Catatan untuk Mobile App:** Setelah mendapatkan `upload_url`, aplikasi akan melakukan `http.put(upload_url, body: fileBytes)` secara langsung.

### C. Endpoint Generate Download URL (Pre-Signed GET)
Meminta URL sementara untuk mengunduh (download) file backup spesifik.

- **URL:** `POST /api/v1/backups/download-url`
- **Headers:** `Authorization: Bearer <user_token>`
- **Request Body:**
```json
{
  "file_name": "7077601022884802_2026-06-28_142030.sql"
}
```
- **Deskripsi Backend:** Backend memastikan file yang diminta benar-benar milik merchant yang sedang login, lalu men-generate **Pre-Signed URL** untuk operasi HTTP `GET`.
- **Expected Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "download_url": "https://s3.ucentric.id/ukasir/7077601022884802/7077601022884802_2026-06-28_142030.sql?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=..."
  }
}
```

### D. Endpoint Delete Backup
Menghapus file backup spesifik dari S3.

- **URL:** `DELETE /api/v1/backups/{file_name}`
- **Headers:** `Authorization: Bearer <user_token>`
- **Deskripsi Backend:** Backend memastikan `file_name` berada di dalam folder merchant yang sedang login, kemudian mengeksekusi penghapusan objek di S3 menggunakan SDK.
- **Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "File backup berhasil dihapus."
}
```

---

## 4. Keuntungan Skema Ini
1. **Zero Security Leak di Aplikasi Mobile:** Aplikasi uKasir Android/iOS tidak lagi membutuhkan _S3 Access/Secret Key_, juga tidak perlu lagi menulis algoritma kompleks HMAC-SHA256 AWS Signature V4 di dalam bahasa Dart.
2. **Privasi Terjamin:** Backend API memiliki kontrol penuh untuk mengecek otentikasi. Akun Merchant A tidak akan bisa mengambil _Pre-signed URL_ untuk memanipulasi _file_ cadangan (backup) milik Merchant B, karena pembatasan _namespace/prefix_ diatur langsung di _logic_ Server.
3. **Fleksibilitas Infra:** Jika besok perusahaan ingin pindah dari MinIO ke layanan Amazon S3 asli, Google Cloud Storage, atau Alibaba OSS, aplikasi mobile tidak perlu di-update sama sekali. Cukup Backend yang melakukan _update_ dependensi SDK.
