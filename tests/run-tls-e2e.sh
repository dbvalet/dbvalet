#!/usr/bin/env bash
# Run inside the same unlocked test keyring session as the regular e2e suite.
set -euo pipefail

major=${1:?pass the PostgreSQL major version}
cd "$(dirname "$0")/.."
temp_root=${RUNNER_TEMP:-$PWD/target}
mkdir -p "$temp_root"
fixture=$(mktemp -d "$temp_root/dbvalet-e2e-tls.XXXXXX")
containers=()

cleanup() {
    if ((${#containers[@]})); then
        docker rm -fv "${containers[@]}" >/dev/null || true
    fi
    rm -rf "$fixture"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 \
    -keyout "$fixture/ca.key" -out "$fixture/ca.crt" -subj /CN=dbvalet-e2e-ca \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign

make_leaf() {
    local name=$1 host=$2 san=$3
    openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$host" \
        -keyout "$fixture/$name.key" -out "$fixture/$name.csr"
    printf '%s\n' basicConstraints=critical,CA:FALSE \
        keyUsage=critical,digitalSignature,keyEncipherment extendedKeyUsage=serverAuth \
        "subjectAltName=$san" > "$fixture/$name.ext"
    openssl x509 -req -days 2 -sha256 \
        -in "$fixture/$name.csr" -out "$fixture/$name.crt" \
        -CA "$fixture/ca.crt" -CAkey "$fixture/ca.key" -CAcreateserial \
        -extfile "$fixture/$name.ext"
}

make_leaf valid localhost DNS:localhost,IP:127.0.0.1
make_leaf wrong wrong-host.example.test DNS:wrong-host.example.test
rm -f "$fixture/ca.key"

start_postgres() {
    local name=$1 container
    container=$(docker run -d --cpus 0.5 --publish 127.0.0.1::5432 \
        -e POSTGRES_PASSWORD=e2e-throwaway -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
        --mount "type=bind,src=$fixture/$name.key,dst=/fixture/server.key,readonly" \
        --mount "type=bind,src=$fixture/$name.crt,dst=/fixture/server.crt,readonly" \
        --entrypoint sh "postgres:$major" -euc '
            install -d /run/dbvalet-tls
            install -o postgres -g postgres -m 0600 /fixture/server.key /run/dbvalet-tls/server.key
            exec docker-entrypoint.sh postgres -c ssl=on \
                -c ssl_cert_file=/fixture/server.crt -c ssl_key_file=/run/dbvalet-tls/server.key
        ')
    containers+=("$container")
}

published_port() {
    local address
    address=$(docker port "$1" 5432/tcp)
    printf '%s\n' "${address##*:}"
}

wait_for_postgres() {
    local container=$1 port=$2 deadline=$((SECONDS + 60))
    until pg_isready -q -h 127.0.0.1 -p "$port" -U postgres -d postgres -t 2; do
        if ((SECONDS >= deadline)); then
            docker logs "$container" >&2
            return 1
        fi
        sleep 1
    done
}

start_postgres valid
start_postgres wrong
tls_port=$(published_port "${containers[0]}")
wrong_host_port=$(published_port "${containers[1]}")
wait_for_postgres "${containers[0]}" "$tls_port"
wait_for_postgres "${containers[1]}" "$wrong_host_port"

DBVALET_E2E_CA_CERT="$fixture/ca.crt" \
DBVALET_E2E_TLS_PORT="$tls_port" \
DBVALET_E2E_WRONG_HOST_PORT="$wrong_host_port" \
    cargo test --locked --test e2e_tls -- --ignored
