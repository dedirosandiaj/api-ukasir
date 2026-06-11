# 📊 Hasil Load Testing TPS — Ukasir API

> **Tanggal Pengujian:** 11 Juni 2026  
> **Environment:** Development (`https://development.api.ukasir.id`)  
> **Branch:** `development`  
> **Tools:** [k6](https://k6.io) v2.0.0 by Grafana

---

## Perbandingan Hasil: 50 VUs vs 1000 VUs

| Metrik | 🟢 Normal Load (50 VUs) | 🔴 Stress Test (1000 VUs) |
|---|---|---|
| **TPS (req/s)** | **~45.66 req/s** | **~366.74 req/s** |
| **Total Request** | 1.400 | 22.571 |
| **Durasi** | 30 detik | 60 detik |
| **Success Rate** | **100%** | **99.98%** |
| **Failed Request** | 0 | 3 (0.01%) |
| **Latency Avg** | 58.68 ms | 476.25 ms |
| **Latency Median** | 26.25 ms | 567.86 ms |
| **Latency Min** | 13.97 ms | 13.06 ms |
| **Latency Max** | 565.95 ms | 1.39 detik |
| **p90** | 120.99 ms | 935.10 ms |
| **p95** | 128.5 ms ✅ | 963.15 ms ✅ |
| **Threshold** | p95 < 500ms ✅ | p95 < 2000ms ✅ |

---

## 🟢 Test 1: Normal Load — 50 Virtual Users

### Konfigurasi
| Parameter | Nilai |
|---|---|
| **Endpoint** | `POST /v1/cashier-transactions` |
| **Virtual Users (VUs)** | 50 VUs |
| **Durasi** | 30 detik |
| **Mode Midtrans** | Mock (`MOCK_MIDTRANS=true`) |

### Hasil

| Metrik | Nilai |
|---|---|
| 🚀 **TPS** | **~45.66 req/s** |
| ✅ **Success Rate** | **100%** (1400 / 1400) |
| ❌ **Failed** | 0 |
| ⏱️ **Latency Avg** | 58.68 ms |
| ⏱️ **Latency p95** | 128.5 ms |

### Kesimpulan
Server sangat stabil di beban normal. Zero failure, latency ringan.

---

## 🔴 Test 2: Stress Test — 1000 Virtual Users (Ramp-Up)

### Konfigurasi
| Parameter | Nilai |
|---|---|
| **Endpoint** | `POST /v1/cashier-transactions` |
| **Pola VUs** | Ramp-up bertahap hingga 1000 VUs |
| **Stage 1** | 15 detik → 200 VUs |
| **Stage 2** | 15 detik → 500 VUs |
| **Stage 3** | 15 detik → 1000 VUs |
| **Stage 4** | 15 detik tahan di 1000 VUs |
| **Durasi Total** | 60 detik |
| **Mode Midtrans** | Mock (`MOCK_MIDTRANS=true`) |

### Hasil

| Metrik | Nilai |
|---|---|
| 🚀 **TPS** | **~366.74 req/s** |
| ✅ **Success Rate** | **99.98%** (22.568 / 22.571) |
| ❌ **Failed** | 3 (0.01%) |
| ⏱️ **Latency Avg** | 476.25 ms |
| ⏱️ **Latency p95** | 963.15 ms ✅ |
| ⏱️ **Latency Max** | 1.39 detik |
| 📡 **Data Diterima** | 20 MB (326 kB/s) |
| 📡 **Data Dikirim** | 6.2 MB (100 kB/s) |

### Kesimpulan
Server **luar biasa tangguh** bahkan di beban ekstrim 1000 VUs serentak. Hanya 3 request gagal dari 22.571 (0.01%), dan latency masih jauh di bawah batas 2 detik.

---

## 📈 Analisis Kapasitas

Berdasarkan Stress Test 1000 VUs:

| Skala Waktu | Kapasitas |
|---|---|
| **Per Detik** | ~367 transaksi |
| **Per Menit** | ~22.000 transaksi |
| **Per Jam** | ~1.320.000 transaksi |
| **Per Hari** | ~31.680.000 transaksi |

### Peningkatan TPS (50 VUs → 1000 VUs)
- TPS naik dari **45 → 366 req/s** (~**8x lipat**)
- Server masih stabil meski beban naik **20x lipat**

> **Kesimpulan Umum:** API Ukasir memiliki performa dan skalabilitas yang **sangat baik** untuk skala platform kasir UMKM. Server mampu menangani lonjakan trafik ekstrim dengan tetap menjaga keandalan di atas 99.98%.

---

## 🔧 Catatan Teknis

| Item | Status |
|---|---|
| Kode mock Midtrans | Di branch `development` saja |
| Rate Limiter | Dinonaktifkan otomatis saat `MOCK_MIDTRANS=true` |
| Branch `main` (Production) | ✅ Tidak terpengaruh, tetap bersih |
| Cara revert | `git checkout main` |

---

## ▶️ Cara Mengulangi Test

```bash
# Normal Load (50 VUs)
k6 run \
  -e BASE_URL=https://development.api.ukasir.id \
  -e API_KEY=<API_KEY_DEV> \
  -e API_SECRET=<API_SECRET_DEV> \
  -e TOKEN_NUMBER=9190-4957-3083-9321 \
  load-test-cashier.js

# Stress Test (1000 VUs) — pastikan konfigurasi di load-test-cashier.js sudah menggunakan stages
k6 run \
  -e BASE_URL=https://development.api.ukasir.id \
  -e API_KEY=<API_KEY_DEV> \
  -e API_SECRET=<API_SECRET_DEV> \
  -e TOKEN_NUMBER=9190-4957-3083-9321 \
  load-test-cashier.js
```
