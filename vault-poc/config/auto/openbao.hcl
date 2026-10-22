# Целевой кластер: распечатывается автоматически через transit Unsealer'а.
# Блок seal "transit" лежит в seal.hcl (его генерирует auto_unseal_demo.py вместе с токеном).
ui            = false
disable_mlock = true
api_addr      = "https://bao-auto:8200"
cluster_addr  = "https://bao-auto:8201"

storage "raft" {
  path    = "/openbao/file"
  node_id = "bao-auto"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/openbao/tls/tls.crt"
  tls_key_file  = "/openbao/tls/tls.key"
}
