#!/usr/bin/env sh
# Self-signed certificate for the local TLS terminator.
# For a real deployment, use a certificate from your CA or Let's Encrypt.
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$DIR"

openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$DIR/gateway.key" \
    -out "$DIR/gateway.crt" \
    -subj "/CN=zta-gateway.local/O=Zero Trust Lab" \
    -addext "subjectAltName=DNS:localhost,DNS:zta-gateway.local,IP:127.0.0.1"

chmod 600 "$DIR/gateway.key"
echo "Wrote $DIR/gateway.crt and $DIR/gateway.key"
echo "Start the terminator with: docker compose --profile tls up -d tls-proxy"
