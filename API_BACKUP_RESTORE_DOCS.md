# API Documentation: Backup & Restore S3

Dokumentasi ini ditujukan bagi tim Mobile (Android/iOS/Flutter) untuk berintegrasi dengan fitur Backup & Restore uKasir. 
Sistem ini menggunakan mekanisme **Pre-Signed URL** untuk memastikan keamanan tingkat tinggi; kredensial S3 tidak pernah terekspos ke sisi klien. 

Semua *endpoint* di bawah ini sudah terisolasi antar-*merchant*. Anda hanya bisa mengakses folder dan file milik *merchant* Anda sendiri yang divalidasi dari *Bearer Token*.

---

## 🔐 Otentikasi (Global)
Setiap permintaan ke *endpoint* Backup & Restore **wajib** menyertakan HTTP Header `Authorization` dengan skema `Bearer`.

- **Header Name:** `Authorization`
- **Value:** `Bearer <token_number_merchant>` (Contoh: `Bearer 1234-5678-9012-3456`)

---

## 1. List Backups (Melihat Daftar Backup)
Mengambil daftar seluruh file backup (berakhiran `.sql` atau `.db`) yang ada di folder S3 merchant yang sedang login.

- **URL:** `GET /v1/backups`
- **Headers:** `Authorization: Bearer <token_merchant>`
- **Response Sukses (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "file_name": "7077601022884802_2026-06-28_142030.sql",
      "date": "2026-06-28",
      "time": "14:20:30",
      "size": "450.5KB"
    }
  ]
}
```

---

## 2. Generate Upload URL (Meminta Izin Upload)
Meminta URL sementara (berlaku selama 10 menit) untuk meng-upload file backup baru ke server.

- **URL:** `POST /v1/backups/upload-url`
- **Headers:** `Authorization: Bearer <token_merchant>`
- **Request Body (JSON):**
```json
{
  "file_name": "backup_db_hari_ini.sql",
  "content_type": "application/octet-stream"
}
```
- **Response Sukses (200 OK):**
```json
{
  "success": true,
  "data": {
    "upload_url": "https://s3.ucentric.id/ukasir/1234-5678-9012-3456/backup_db_hari_ini.sql?X-Amz-Algorithm=..."
  }
}
```

### 💡 Workflow Upload untuk Mobile:
1. Panggil *endpoint* di atas (`POST /v1/backups/upload-url`).
2. Ambil nilai `upload_url` dari *response*.
3. Lakukan **HTTP PUT** langsung ke `upload_url` tersebut dengan *body* berisi *byte array / file binary* dari file database di lokal. (Tidak perlu *header* otentikasi uKasir lagi saat menembak URL S3 ini).
   - *Contoh Pseudo-code Dart/Flutter:* 
     ```dart
     http.put(Uri.parse(uploadUrl), body: fileBytes, headers: {'Content-Type': 'application/octet-stream'});
     ```

---

## 3. Generate Download URL (Meminta Izin Download)
Meminta URL sementara (berlaku selama 10 menit) untuk mengunduh file backup yang sudah ada.

- **URL:** `POST /v1/backups/download-url`
- **Headers:** `Authorization: Bearer <token_merchant>`
- **Request Body (JSON):**
```json
{
  "file_name": "backup_db_hari_ini.sql"
}
```
- **Response Sukses (200 OK):**
```json
{
  "success": true,
  "data": {
    "download_url": "https://s3.ucentric.id/ukasir/1234-5678-9012-3456/backup_db_hari_ini.sql?X-Amz-Algorithm=..."
  }
}
```

### 💡 Workflow Download untuk Mobile:
1. Panggil *endpoint* di atas (`POST /v1/backups/download-url`).
2. Ambil nilai `download_url` dari *response*.
3. Lakukan **HTTP GET** (atau gunakan library *downloader*) langsung ke `download_url` tersebut. File akan langsung terunduh. (Tidak perlu *header* otentikasi uKasir).

---

## 4. Delete Backup (Menghapus File Backup)
Menghapus file backup spesifik dari S3. 

- **URL:** `DELETE /v1/backups/{file_name}`
- **Headers:** `Authorization: Bearer <token_merchant>`
- **Contoh URL:** `DELETE /v1/backups/backup_db_hari_ini.sql`
- **Response Sukses (200 OK):**
```json
{
  "success": true,
  "message": "File backup berhasil dihapus."
}
```

---

## Kemungkinan Error yang akan Dihadapi

- **401 Unauthorized:**
```json
{
  "success": false,
  "message": "Unauthorized" 
}
// Atau
{
  "success": false,
  "message": "Invalid or inactive token"
}
```
*Pastikan format Header `Authorization: Bearer <token>` benar dan token masih aktif.*

- **400 Bad Request:**
```json
{
  "success": false,
  "message": "file_name required"
}
```
*Pastikan `file_name` dikirimkan di dalam JSON body saat memanggil request POST.*

- **500 Internal Server Error:**
```json
{
  "success": false,
  "message": "S3 Error" // atau "DB Error"
}
```
*Terjadi gangguan komunikasi antara backend uKasir dan server S3 MinIO atau Database, silakan dicoba beberapa saat lagi.*
