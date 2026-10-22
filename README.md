# KMS suite

Хранение мастер-ключей с порогом k из n и crypto-shredding, плюс окружение вокруг него: аудит, пороговые подписи, идентичность сервисов, защита поставок и E2EE-мессенджер.

| Папка | Что это | Статус проверки |
|---|---|---|
| `threshold-kms/` | Самописный Threshold KMS: Shamir/Feldman VSS, 5 узлов, mTLS, RBAC по CN координатора | 29/29 проверок на 5 живых контейнерах (образ собран локально; настоящий Dockerfile не собирался) |
| `transparency-log/` | Журнал прозрачности (Merkle tree, RFC 9162): неизменяемый аудит KMS, монитор ловит переписывание истории | 174 теста + мутационная проверка; запущен демо-сценарий |
| `threshold-signing/` | DKG без дилера + пороговая подпись FROST (Ed25519): подпись проверяется обычным Ed25519-верификатором | 53 теста, 22 мутации (все пойманы, 1 эквивалентная); демо запущено |
| `vault-poc/` | Тот же сценарий на OpenBao/Vault: Shamir unseal, transit, AppRole, crypto-shredding, auto-unseal через второй сервер | Не запускался на живом сервере; проверен только синтаксис |
| `e2ee-messenger/` | X3DH + Double Ratchet (по спецификациям Signal), PQXDH (X25519 + ML-KEM), ротация SPK, недоверенный relay, TOFU и safety number | 60 тестов (forward secrecy, post-compromise, out-of-order, подмены) + мутации |
| `workload-identity/` | Модель SPIFFE/SPIRE: короткоживущие SVID, join-токены и TPM-аттестация узлов, ротация ключей и CA; в KMS включается `COORDINATOR_SPIFFE_ID` | 70 тестов: настоящие TLS 1.3-рукопожатия, аттестация узла по модели TPM (атаки на протокол) + мутации |
| `release-guard/` | Цепочка поставок: детерминированный архив, CycloneDX SBOM, DSSE + in-toto provenance, журнал прозрачности, политика, подпись FROST | 53 теста + 33 мутации; ML-DSA (гибрид с Ed25519), воспроизводимый wheel |
| `formal-verification/` | Символьный анализ X3DH/PQXDH/Double Ratchet: все наборы утечек ключей, мост к реальному коду, активные атаки; модель на ProVerif (не запускалась) | 39 тестов + 11 мутаций; **нашёл 2 слабости кода** (имя отправителя вне криптографии, нет ротации SPK) |

## threshold-kms
    cd threshold-kms
    bash setup_mtls.sh          # сертификаты в certs/ (SAN, EKU), ca.key потом убрать
    docker compose up --build -d
    # ключи в certs/ и db_data/ должны принадлежать uid 1000 (см. Dockerfile)
    # координатор: cd src && python coordinator.py (CERTS_DIR=../certs)

## Тесты и аудит
`threshold-kms/tests` (49 тестов: свойства, сравнение с `cryptography`, фаззинг API) и отчёт `threshold-kms/AUDIT.md`.
CI: `.github/workflows/tests.yml`.

## transparency-log
    cd transparency-log && pip install -r requirements.txt && python demo.py
    # аудит из KMS: AUDIT_LOG_URL / AUDIT_LOG_TOKEN в окружении узлов. См. transparency-log/README.md

## threshold-signing
    cd threshold-signing && pip install -r requirements.txt -r ../transparency-log/requirements.txt && python demo.py
    # тесты: cd tests && pip install -r requirements-test.txt && pytest

## vault-poc
    cd vault-poc
    ./make_certs.sh
    # ручной Shamir:   docker compose --profile manual up -d bao-1 && python demo.py
    # auto-unseal:     docker compose --profile auto up -d unsealer && python auto_unseal_demo.py
См. `vault-poc/README.md`.

## e2ee-messenger
    cd e2ee-messenger && pip install -r requirements.txt pytest hypothesis && pytest && python demo.py

## workload-identity
    cd workload-identity && pip install -r requirements.txt pytest && pytest && python demo.py
    python issue_kms_certs.py certs 5     # SVID для KMS; затем COORDINATOR_SPIFFE_ID=spiffe://kms.local/coordinator

## release-guard
    cd release-guard && pip install -r requirements.txt pytest && pytest && python demo.py
    # использует ../transparency-log/src и ../threshold-signing/src

Везде: учебные реализации, не аудированы; ограничения перечислены в README каждой папки.

## formal-verification
    cd formal-verification && pip install -r requirements.txt pytest && pytest && python demo.py
    # x3dh.pv: proverif x3dh.pv (ProVerif на вашей машине; здесь не запускалась)

## Как выбирать
- Учёба, демонстрация идеи, разбор устройства пороговой схемы: `threshold-kms`.
- Реальные данные: Vault/OpenBao (или облачный KMS/HSM), а свой код оставить как пример.
