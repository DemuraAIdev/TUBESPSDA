# Hall Of Fame - Kelompok 7 TUBES PSDA

Aplikasi **Hall Of Fame** adalah aplikasi pencatatan skor leaderboard interaktif berbasis terminal (TUI) yang dikembangkan menggunakan C++ dan library [FTXUI](https://github.com/ArthurSonzogni/FTXUI).

## ✨ Fitur Utama
- **Sistem Login Keamanan**: Autentikasi admin dengan proteksi *lockout* jika salah password berkali-kali.
- **Manajemen Player**: Menambah data pemain dan skor ke dalam daftar.
- **Leaderboard Interaktif**: Menampilkan data dalam bentuk tabel yang rapi.
- **Algoritme Sorting**: Menggunakan **Insertion Sort** untuk mengurutkan skor dari yang tertinggi (descending).
- **Antarmuka Modern**: UI berbasis terminal yang responsif dengan dukungan navigasi keyboard.

## 🛠️ Persyaratan Sistem
Sebelum menjalankan aplikasi, pastikan sistem Anda memiliki:
- **CMake** (minimal versi 3.14)
- **C++ Compiler** yang mendukung standar **C++17** (seperti GCC atau Clang)
- **Koneksi Internet** (hanya saat build pertama kali untuk mendownload library FTXUI secara otomatis)

## 🚀 Cara Menjalankan

Ikuti langkah-langkah berikut untuk melakukan kompilasi dan menjalankan aplikasi:

### 1. Masuk ke direktori proyek
Buka terminal dan arahkan ke folder proyek ini.

### 2. Buat direktori build
Gunakan direktori terpisah untuk proses build agar file sumber tetap rapi:
```bash
mkdir build
cd build
```

### 3. Konfigurasi Proyek dengan CMake
Jalankan perintah berikut untuk menyiapkan build environment:
```bash
cmake ..
```

### 4. Kompilasi (Build)
Lakukan kompilasi kode sumber menjadi executable:
```bash
make
```

### 5. Jalankan Aplikasi
Setelah proses build selesai, jalankan file executable yang dihasilkan:
```bash
./HallOfFame
```

## 🔐 Informasi Login Default
- **Username**: `admin`
- **Password**: `admin123`

## ⌨️ Kontrol Navigasi
- **Panah (Arrow Keys) / Tab**: Berpindah antar tombol atau input field.
- **Enter**: Memilih tombol atau melakukan aksi.
- **Esc**: Kembali ke menu sebelumnya atau keluar dari aplikasi.

---
### Disusun Oleh - Kelompok 7:
1. **Abdul Vaiz Vahry Iskandar** - G1A025063
2. **Nadhif Arwendo** - G1A025077
3. **Ivo Indah Ghazeta** - G1A025087
