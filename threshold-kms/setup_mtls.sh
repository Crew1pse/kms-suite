#!/bin/bash
set -euo pipefail
umask 077
mkdir -p certs && cd certs

DAYS=365
ext() { # $1=CN  $2=SAN
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=%s\n' "$2"
}

echo "Генерация Root CA..."
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days $DAYS -nodes -subj "/CN=KMS-Root-CA"

echo "Генерация сертификатов для 5 узлов..."
for i in {1..5}; do
  openssl req -newkey rsa:2048 -keyout node-$i.key -out node-$i.csr -nodes -subj "/CN=kms-node-$i"
  openssl x509 -req -in node-$i.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out node-$i.crt -days $DAYS \
    -extfile <(ext "kms-node-$i" "DNS:localhost,DNS:kms-node-$i,IP:127.0.0.1")
done

echo "Генерация сертификата для Координатора..."
openssl req -newkey rsa:2048 -keyout coord.key -out coord.csr -nodes -subj "/CN=kms-coordinator"
openssl x509 -req -in coord.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out coord.crt -days $DAYS \
  -extfile <(ext "kms-coordinator" "DNS:kms-coordinator,DNS:localhost,IP:127.0.0.1")

rm -f *.csr
chmod 600 *.key
chmod 644 *.crt
echo "Все сертификаты успешно сгенерированы в папке certs/!"
echo "ВАЖНО: ca.key уберите с рабочей машины после выпуска сертификатов."
