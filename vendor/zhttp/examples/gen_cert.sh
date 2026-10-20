#!/usr/bin/env bash
set -e

mkdir -p cert

cd cert

# Generate EC private key
openssl ecparam -genkey -name prime256v1 -out key.pem

# Generate self-signed certificate
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=localhost"

echo "Certificates generated in examples/cert/"
ls -la
