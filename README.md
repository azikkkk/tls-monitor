# TLS Monitor — Netlify Deployment

Real Node.js TLS handshake vasitəsilə SSL/TLS sertifikat analizi.

## Layihə strukturu

```
tls-monitor/
├── netlify.toml              ← Netlify konfiqurasiyası
├── package.json              ← Asılılıqlar
├── public/
│   └── index.html            ← Frontend (standalone)
└── netlify/
    └── functions/
        └── check-tls.js      ← Backend (Node.js TLS inspector)
```

## Backend necə işləyir?

`netlify/functions/check-tls.js` — Node.js-in daxili `tls` modulundan istifadə edir:

- **Həqiqi TLS handshake** — birbaşa serverə qoşulur
- **DNS həlli** — serverin IP ünvanını alır
- **Sertifikat analizi** — subject, issuer, SAN, fingerprint, chain
- **Cipher analizi** — PFS, AEAD, RC4/NULL aşkarlaması
- **Zəiflik yoxlaması** — köhnə protokollar, zəif açarlar, SHA-1
- **Qiymət hesablaması** — A+ / A / B / F / T
- **Xarici asılılıq yoxdur** — `node-forge` paketi isteğe bağlı

## Deploy etmə (3 addım)

### 1. GitHub-a yüklə

```bash
cd tls-monitor
git init
git add .
git commit -m "TLS Monitor initial commit"
git remote add origin https://github.com/USERNAME/tls-monitor.git
git push -u origin main
```

### 2. Netlify-da yeni sayt yarat

1. [app.netlify.com](https://app.netlify.com) → **Add new site** → **Import an existing project**
2. GitHub repo-nu seç: `tls-monitor`
3. Build settings:
   - **Build command:** *(boş burax)*
   - **Publish directory:** `public`
4. **Deploy site** düyməsinə bas

### 3. Deploy tamamlandı! 🎉

Netlify avtomatik olaraq:
- `public/index.html` → frontend kimi deploy edir
- `netlify/functions/check-tls.js` → `/.netlify/functions/check-tls` ünvanında
- `netlify.toml`-dakı redirect → `/api/check-tls` olaraq xarici istifadəyə açır

## Alternatif: Netlify CLI ilə local test

```bash
npm install
npm run dev
# → http://localhost:8888 ünvanında işləyir
```

## API endpoint

```
POST /api/check-tls
Content-Type: application/json

{
  "domain": "example.com"
}
```

Cavab:
```json
{
  "domain": "example.com",
  "port": 443,
  "ipAddress": "93.184.216.34",
  "status": "SECURE",
  "score": 95,
  "tlsGrade": "A+",
  "tls": {
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "forwardSecrecy": true
  },
  "certificate": {
    "subject": "CN=example.com",
    "issuer": "CN=DigiCert...",
    "daysRemaining": 245,
    "fingerprintSHA256": "AA:BB:..."
  },
  ...
}
```

## Xüsusiyyətlər

| Xüsusiyyət | Açıqlama |
|---|---|
| Real TLS handshake | Node.js `tls.connect()` — heç bir xarici API yox |
| Cipher analizi | PFS, AEAD, RC4/NULL/EXPORT aşkarlaması |
| Sertifikat zənciri | Kök CA-ya qədər tam chain |
| Zəiflik yoxlaması | Köhnə protokollar, zəif açarlar, SHA-1 |
| AI izahat | Claude API ilə hər problemin ətraflı izahı |
| Tarixçə | LocalStorage-da son 8 skan |
| Non-standard portlar | `example.com:8443` formatı dəstəklənir |

## Texniki qeydlər

- Backend Netlify serverindən real TCP əlaqəsi qurur
- `rejectUnauthorized: false` — bütün sertifikatları yoxlamaq üçün (özü-özünə imzalanmışlar daxil)
- `getPeerCertificate(true)` — tam sertifikat zənciri
- Timeout: 10 saniyə
