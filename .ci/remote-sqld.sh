#!/usr/bin/env bash
# Public synthetic data only. No Turso credentials are required or read.
set -euo pipefail
sqld_dir=$(mktemp -d)
curl -fsSL -A cvld-library-maintenance \
  https://github.com/tursodatabase/libsql/releases/download/libsql-server-v0.24.32/libsql-server-x86_64-unknown-linux-gnu.tar.xz \
  -o "$sqld_dir/server.tar.xz"
printf '%s  %s\n' 71720fc8648c19efef416efebd47145ef59b62e198770533530a858e1336879f "$sqld_dir/server.tar.xz" | sha256sum -c -
tar -xJf "$sqld_dir/server.tar.xz" -C "$sqld_dir"
sqld_binary=$(find "$sqld_dir" -type f -name sqld -print -quit)
"$sqld_binary" --db-path "$sqld_dir/database" --http-listen-addr 127.0.0.1:8080 >"$sqld_dir/server.log" 2>&1 &
sqld_pid=$!
proxy_pid=
trap 'kill "$sqld_pid" ${proxy_pid:+"$proxy_pid"} 2>/dev/null || true; wait "$sqld_pid" 2>/dev/null || true' EXIT
for attempt in $(seq 1 40); do
  if curl -fsS -A cvld-library-maintenance http://127.0.0.1:8080/health >/dev/null; then break; fi
  sleep 0.25
done
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=SyntheticTestCA \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -keyout "$sqld_dir/ca-key.pem" -out "$sqld_dir/ca.pem" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout "$sqld_dir/key.pem" -out "$sqld_dir/request.pem" 2>/dev/null
cat > "$sqld_dir/extensions.cnf" <<'CERT'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
CERT
openssl x509 -req -in "$sqld_dir/request.pem" -CA "$sqld_dir/ca.pem" \
  -CAkey "$sqld_dir/ca-key.pem" -CAcreateserial -days 1 \
  -extfile "$sqld_dir/extensions.cnf" -out "$sqld_dir/cert.pem" 2>/dev/null
python3 .ci/tls-proxy.py "$sqld_dir/cert.pem" "$sqld_dir/key.pem" &
proxy_pid=$!
for attempt in $(seq 1 40); do
  if curl -fsS --cacert "$sqld_dir/ca.pem" -A cvld-library-maintenance https://localhost:8443/health >/dev/null; then break; fi
  sleep 0.25
done
SSL_CERT_FILE="$sqld_dir/ca.pem" SQLD_URL=https://localhost:8443 cargo test --locked remote_sqld_round_trip -- --exact
