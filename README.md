# Pantau

**Pantau** — CLI inspeksi keamanan link & domain.

Deteksi URL mencurigakan, phishing, dan penipuan dengan pola khas Indonesia (palsu BPJS, paket, banking, dll).

## Instalasi

```bash
pip install pantau
```

Atau langsung dari repo:

```bash
pip install git+https://github.com/vtino17/pantau.git
```

## Usage

```bash
# Periksa URL mencurigakan
pantau check https://shorturl.at/abc123

# Lihat destinasi asli link pendek
pantau expand https://s.id/XYZ

# Lihat daftar pola penipuan yang dideteksi
pantau patterns

# Periksa domain
pantau check tokopedia-flashsale.com
```

## Fitur

- Deteksi link phishing dengan pola khas Indonesia
- URL shortener expansion otomatis
- Skor risiko + alasan detail
- Pola penipuan terupdate: BPJS, paket, banking, pinjol, undian
- 100% offline (kecuali expand URL)
