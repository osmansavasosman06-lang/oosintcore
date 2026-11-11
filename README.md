# OSINTCORE v3 — Mail Doğrulamalı Güvenli Çalışma Alanı

## Gereksinimler
- Node.js 20+
- hCaptcha hesabı ve bu site için Sitekey + Secret
- Gmail SMTP (osintcore@gmail.com) Uygulama Şifresi

## Yerelde Çalıştırma
1. `npm install`
2. `.env.example` dosyasını `.env` olarak kopyala ve gerekli ayarları (SMTP_PASS, HCAPTCHA_SECRET vb.) doldur.
3. `npm start` ile başlat.
