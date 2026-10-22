# Unsealer: отдельный сервер, чей transit-ключ "autounseal" оборачивает мастер-ключ целевого кластера.
# Сам Unsealer запечатывается вручную (Shamir) - классическая "курица и яйцо" on-prem схемы.
ui            = false
disable_mlock = true
api_addr      = "https://unsealer:8200"
cluster_addr  = "https://unsealer:8201"

storage "raft" {
  path    = "/openbao/file"
  node_id = "unsealer"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/openbao/tls/tls.crt"
  tls_key_file  = "/openbao/tls/tls.key"
}
