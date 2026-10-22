# Демо-конфиг: один узел, raft-хранилище, TLS. Для продакшена: 3-5 узлов raft + auto-unseal.
ui            = false
disable_mlock = true
api_addr      = "https://localhost:8200"
cluster_addr  = "https://127.0.0.1:8201"

storage "raft" {
  path    = "/openbao/file"
  node_id = "bao-1"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/openbao/tls/tls.crt"
  tls_key_file    = "/openbao/tls/tls.key"
  # mTLS для клиентов: включите, когда будете выдавать клиентские сертификаты
  # tls_client_ca_file                = "/openbao/tls/ca.crt"
  # tls_require_and_verify_client_cert = true
}
