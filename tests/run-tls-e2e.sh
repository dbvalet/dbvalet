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

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp521r1 -nodes -days 2 -sha512 \
    -keyout "$fixture/ec-ca.key" -out "$fixture/ec-ca.crt" -subj /CN=dbvalet-e2e-ec-ca \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign

cat "$fixture/ca.crt" "$fixture/ec-ca.crt" > "$fixture/cas.pem"

make_leaf() {
    local name=$1 host=$2 san=$3 ca=$4 digest=$5 key_type=$6
    shift 6
    if [[ "$key_type" == ec521 ]]; then
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:secp521r1 -nodes \
            -subj "/CN=$host" -keyout "$fixture/$name.key" -out "$fixture/$name.csr"
        printf '%s\n' basicConstraints=critical,CA:FALSE \
            keyUsage=critical,digitalSignature extendedKeyUsage=serverAuth \
            "subjectAltName=$san" > "$fixture/$name.ext"
    else
        openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$host" \
            -keyout "$fixture/$name.key" -out "$fixture/$name.csr"
        printf '%s\n' basicConstraints=critical,CA:FALSE \
            keyUsage=critical,digitalSignature,keyEncipherment extendedKeyUsage=serverAuth \
            "subjectAltName=$san" > "$fixture/$name.ext"
    fi
    openssl x509 -req -days 2 "-$digest" \
        -in "$fixture/$name.csr" -out "$fixture/$name.crt" \
        -CA "$fixture/$ca.crt" -CAkey "$fixture/$ca.key" -CAcreateserial \
        -extfile "$fixture/$name.ext" "$@"
}

make_leaf valid localhost DNS:localhost,IP:127.0.0.1 ca sha256 rsa
make_leaf ec512 localhost DNS:localhost,IP:127.0.0.1 ec-ca sha512 ec521
make_leaf rsapss localhost DNS:localhost,IP:127.0.0.1 ca sha256 rsa \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest
make_leaf wrong wrong-host.example.test DNS:wrong-host.example.test ca sha256 rsa
rm -f "$fixture/ca.key" "$fixture/ec-ca.key"

start_postgres() {
    local name=$1 container
    container=$(docker run -d --cpus 0.5 --publish 127.0.0.1::5432 \
        -e POSTGRES_PASSWORD=e2e-throwaway -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
        --mount "type=bind,src=$fixture,dst=/fixture,readonly" \
        --entrypoint sh "postgres:$major" -euc '
            install -d /run/dbvalet-tls
            install -o postgres -g postgres -m 0644 "/fixture/$1.crt" /run/dbvalet-tls/server.crt
            install -o postgres -g postgres -m 0600 "/fixture/$1.key" /run/dbvalet-tls/server.key
            exec docker-entrypoint.sh postgres -c ssl=on \
                -c ssl_cert_file=/run/dbvalet-tls/server.crt \
                -c ssl_key_file=/run/dbvalet-tls/server.key
        ' sh "$name")
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

wait_for_served_cert() {
    local port=$1 cert_path=$2 expected served attempt
    expected=$(openssl x509 -in "$cert_path" -noout -fingerprint -sha256)
    for attempt in $(seq 1 15); do
        served=$(openssl s_client -starttls postgres -connect "127.0.0.1:$port" \
            -servername localhost </dev/null 2>/dev/null \
            | openssl x509 -noout -fingerprint -sha256 2>/dev/null) || served=
        if [[ "$served" == "$expected" ]]; then
            return 0
        fi
        sleep 1
    done
    printf 'PostgreSQL on port %s did not serve %s\n' "$port" "$cert_path" >&2
    return 1
}

start_postgres valid
start_postgres wrong
tls_port=$(published_port "${containers[0]}")
wrong_host_port=$(published_port "${containers[1]}")
wait_for_postgres "${containers[0]}" "$tls_port"
wait_for_postgres "${containers[1]}" "$wrong_host_port"

DBVALET_E2E_CA_CERT="$fixture/cas.pem" \
DBVALET_E2E_TLS_PORT="$tls_port" \
DBVALET_E2E_WRONG_HOST_PORT="$wrong_host_port" \
    cargo test --locked --test e2e_tls -- --ignored

for cert in ec512 rsapss; do
    docker exec "${containers[0]}" sh -euc '
        install -o postgres -g postgres -m 0644 "/fixture/$1.crt" /run/dbvalet-tls/server.crt
        install -o postgres -g postgres -m 0600 "/fixture/$1.key" /run/dbvalet-tls/server.key
    ' sh "$cert"
    [[ $(docker exec --user postgres "${containers[0]}" \
        psql -XAtq -v ON_ERROR_STOP=1 -c 'SELECT pg_reload_conf()') == t ]]
    wait_for_served_cert "$tls_port" "$fixture/$cert.crt"
    DBVALET_E2E_CA_CERT="$fixture/cas.pem" \
    DBVALET_E2E_TLS_PORT="$tls_port" \
    DBVALET_E2E_WRONG_HOST_PORT="$wrong_host_port" \
        cargo test --locked --test e2e_tls -- \
            channel_binding_require_succeeds_for_doctor_and_run_over_tls --ignored --exact
done
