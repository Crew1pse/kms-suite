#!/bin/bash
# Только для демо: самоподписанный CA и серверный сертификат с SAN.
set -euo pipefail
mkdir -p tls data/manual data/unsealer data/auto audit config/auto && cd tls
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 30 -nodes -subj "/CN=Demo-CA"
openssl req -newkey rsa:2048 -keyout tls.key -out tls.csr -nodes -subj "/CN=localhost"
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt -days 30 \
  -extfile <(printf 'subjectAltName=DNS:localhost,DNS:bao-1,DNS:unsealer,DNS:bao-auto,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n')
rm -f tls.csr ca.key
chmod 644 tls.key   # DEMO ONLY: контейнерный пользователь должен прочитать ключ
echo "OK -> tls/ca.crt, tls/tls.crt, tls/tls.key"
