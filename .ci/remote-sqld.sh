#!/usr/bin/env bash
# Public synthetic data only. No Turso credentials are required or read.
set -euo pipefail
sqld_dir=$(mktemp -d)
sqld_pid=
proxy_pid=
fixture_phase=download
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  for pid in "$proxy_pid" "$sqld_pid"; do
    if [[ -n "$pid" ]]; then kill -TERM "$pid" 2>/dev/null || true; fi
  done
  for attempt in $(seq 1 50); do
    local alive=false
    for pid in "$proxy_pid" "$sqld_pid"; do
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then alive=true; fi
    done
    if [[ "$alive" == false ]]; then break; fi
    sleep 0.1
  done
  for pid in "$proxy_pid" "$sqld_pid"; do
    if [[ -n "$pid" ]]; then
      kill -KILL "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [[ "$status" != 0 ]]; then
    printf 'Synthetic libSQL fixture failed during %s (exit %s)\n' "$fixture_phase" "$status" >&2
    if [[ -f "$sqld_dir/proxy.log" ]]; then tail -c 2048 "$sqld_dir/proxy.log" >&2; fi
  fi
  # Only this invocation's mktemp directory: archive, synthetic DB and TLS keys.
  rm -rf -- "$sqld_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
curl -fsSL --connect-timeout 15 --max-time 120 -A cvld-library-maintenance \
  https://github.com/tursodatabase/libsql/releases/download/libsql-server-v0.24.32/libsql-server-x86_64-unknown-linux-gnu.tar.xz \
  -o "$sqld_dir/server.tar.xz"
printf '%s  %s\n' 71720fc8648c19efef416efebd47145ef59b62e198770533530a858e1336879f "$sqld_dir/server.tar.xz" | sha256sum -c -
fixture_phase=extraction
tar -xJf "$sqld_dir/server.tar.xz" -C "$sqld_dir"
sqld_binary=$(find "$sqld_dir" -type f -name sqld -print -quit)
test -n "$sqld_binary" && test -x "$sqld_binary"
# The kernel chooses the port while sqld retains its listening socket. The
# proxy discovers only sockets held by this child, never an arbitrary service.
"$sqld_binary" --db-path "$sqld_dir/database" --http-listen-addr 127.0.0.1:0 >"$sqld_dir/server.log" 2>&1 &
sqld_pid=$!
fixture_phase=certificates
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
python3 .ci/tls-proxy.py "$sqld_dir/cert.pem" "$sqld_dir/key.pem" \
  "$sqld_pid" "$sqld_dir/ready" >"$sqld_dir/proxy.log" 2>&1 &
proxy_pid=$!
fixture_phase=startup
for attempt in $(seq 1 150); do
  kill -0 "$sqld_pid" 2>/dev/null || { echo 'Fixture startup failed: owned sqld exited' >&2; exit 1; }
  kill -0 "$proxy_pid" 2>/dev/null || { echo 'Fixture startup failed: owned TLS proxy exited' >&2; exit 1; }
  if [[ -s "$sqld_dir/ready" ]]; then break; fi
  sleep 0.1
done
test -s "$sqld_dir/ready" || { echo 'Fixture startup failed: owned TLS endpoint deadline' >&2; exit 1; }
sqld_url=$(cat "$sqld_dir/ready")
[[ "$sqld_url" =~ ^https://127\.0\.0\.1:[0-9]+$ ]] || { echo 'Fixture startup failed: invalid URL' >&2; exit 1; }
curl -fsS --connect-timeout 2 --max-time 10 --cacert "$sqld_dir/ca.pem" \
  -A cvld-library-maintenance "$sqld_url/health" >/dev/null
kill -0 "$sqld_pid" && kill -0 "$proxy_pid"
echo 'Owned HTTPS fixture ready; running the original libSQL round trip'
fixture_phase=round-trip
SSL_CERT_FILE="$sqld_dir/ca.pem" SQLD_URL="$sqld_url" cargo test --locked remote_sqld_round_trip -- --exact
kill -0 "$sqld_pid" && kill -0 "$proxy_pid"
fixture_phase=complete
