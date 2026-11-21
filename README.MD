# 🛡️ Eclipse IDS — Backend API

Backend service untuk sistem **Eclipse Intrusion Detection System (IDS)**. Layanan ini dibangun menggunakan **FastAPI** dan terhubung ke database cloud **PostgreSQL (Neon.tech)** untuk menyajikan data statistik lalu lintas jaringan, log deteksi intrusi, serta analisis file CSV berbasis model Machine Learning.

---

## 🛠️ Tech Stack

* **Framework:** Python 3.11+ & FastAPI
* **Server:** Uvicorn
* **Database:** PostgreSQL (Hosted on Neon.tech)
* **Data Processing:** Pandas, NumPy, Psycopg2

---

## 📁 Struktur Repository

```text
eclipse-backend/
├── .env                  # Kredensial database lokal (tidak di-push ke Git)
├── .gitignore            # Daftar file/folder yang diabaikan Git
├── ingest_data.py        # Script migrasi & prediksi awal dataset simulasi ke Neon
├── main.py               # Kode utama REST API FastAPI
├── README.md             # Dokumentasi proyek & panduan setup tim
└── requirements.txt      # Daftar dependensi Python
```

---

## 🚀 Panduan Setup Lokal (Untuk Tim Frontend)

Database PostgreSQL sudah ter-hosting secara online di **Neon** dan telah terisi data log deteksi. Kamu **tidak perlu menginstal PostgreSQL** secara lokal maupun menjalankan ulang `ingest_data.py`. Ikuti langkah berikut untuk menjalankan API di laptopmu:

### 1. Clone Repository
```bash
git clone https://github.com/Mhdvk/eclipse-backend.git
cd eclipse-backend
```

### 2. Install Dependensi
*(Disarankan menggunakan virtual environment `venv` terlebih dahulu)*
```bash
pip install -r requirements.txt
```

### 3. Konfigurasi Environment Variable (`.env`)
Buat file baru bernama **`.env`** di dalam folder `eclipse-backend/`, lalu tempel URL koneksi database Neon yang dibagikan di grup tim:
```env
DATABASE_URL=postgresql://user:password@host.aws.neon.tech/neondb?sslmode=require
```

### 4. Jalankan Server FastAPI
```bash
uvicorn main:app --reload --port 8000
```

Setelah server berjalan, API dapat diakses melalui:
* **Base URL:** `http://127.0.0.1:8000`
* **Swagger UI (Dokumentasi Interaktif):** `http://127.0.0.1:8000/docs`
* **OpenAPI Schema (Untuk Import Hoppscotch/Postman):** `http://127.0.0.1:8000/openapi.json`

---

## 📡 Daftar Endpoint API

| Method | Endpoint | Deskripsi | Query / Body Parameters |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/dashboard/summary` | Mengambil ringkasan metrik KPI utama (total traffic, total attack, benign, persentase serangan, jumlah aset terdampak, dan penyerang unik). | — |
| `GET` | `/api/dashboard/traffic-hourly` | Mengambil data agregasi lalu lintas jaringan per jam untuk visualisasi grafik. | — |
| `GET` | `/api/dashboard/top-ips` | Mengambil daftar IP penyerang teratas dan IP aset yang paling sering ditargetkan. | `limit` (opsional, default: `5`) |
| `GET` | `/api/dashboard/logs` | Mengambil daftar log detail lalu lintas jaringan dengan dukungan filter dan pagination. | `label` (`Malicious` / `Benign`), `search_ip`, `page` (default: `1`), `limit` (default: `20`) |
| `POST` | `/api/analyze-csv` | Mengunggah file `.csv` baru untuk diprediksi oleh model ML dan langsung disimpan ke database. | `FormData` dengan key `file` (`.csv`) |

---

## 🧪 Testing Menggunakan Hoppscotch

1. Pastikan server lokal sedang berjalan (`uvicorn main:app --reload --port 8000`).
2. Buka [Hoppscotch](https://hoppscotch.io) $\rightarrow$ buka tab **Collections** $\rightarrow$ klik **Import** $\rightarrow$ pilih **Import from OpenAPI**.
3. Masukkan URL `http://127.0.0.1:8000/openapi.json` (atau import file koleksi `.json` yang dibagikan tim).
4. Atur variabel global `baseUrl` menjadi `http://127.0.0.1:8000` dan klik **Send** pada masing-masing endpoint untuk melihat struktur respons JSON.