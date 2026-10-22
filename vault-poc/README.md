# Vault/OpenBao PoC

Не запускалось на живом сервере при разработке: проверены только синтаксис скриптов, shell и compose.

## 1. Ручной Shamir + transit + AppRole + crypto-shredding
    ./make_certs.sh
    docker compose --profile manual up -d bao-1
    python demo.py          # перед повтором: docker compose down; rm -rf data/manual

## 2. Auto-unseal через transit второго сервера
    ./make_certs.sh
    docker compose --profile auto up -d unsealer
    python auto_unseal_demo.py     # сам поднимает/перезапускает bao-auto
    # повтор с нуля: docker compose --profile auto --profile auto-target down; rm -rf data config/auto/seal.hcl

Файлы `data/*-secrets.json` и `config/auto/seal.hcl` содержат ключи и токен в открытом виде: только для демо.
Образ `openbao/openbao:latest` зафиксируйте на конкретную версию. Для Vault замените образ на `hashicorp/vault`
и пути `/openbao/...` на `/vault/...`.

## Что показывает auto-unseal
- Мастер-ключ целевого кластера оборачивается transit-ключом Unsealer'а; операторы при рестарте не нужны.
- Shamir остаётся у самого Unsealer'а (разовый ручной unseal) и превращается в recovery-ключи у цели.
- Unsealer становится новой точкой отказа: упал или запечатан -> цель не поднимется (fail-closed).
