#!/bin/sh
# Generate the SNI virtual-host test fixtures: a dedicated test CA and three
# server certificates with distinct subjectAltNames, all signed by that CA.
# The CA key is committed on purpose so the fixtures can be regenerated or
# extended without replacing the whole set.
#
# Usage: cd certs/sni && sh generate.sh
set -e

DAYS=10950

openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt \
    -days "$DAYS" -nodes -subj "/CN=picoquic sni test ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

gen_leaf() {
    name="$1"
    san="$2"
    openssl req -newkey rsa:2048 -keyout "$name.key" -out "$name.csr" \
        -nodes -subj "/CN=picoquic sni test $name"
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key \
        -out "$name.crt" -days "$DAYS" -set_serial "0x$(openssl rand -hex 8)" \
        -extfile /dev/stdin <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
EOF
    rm "$name.csr"
}

gen_client() {
    name="$1"
    openssl req -newkey rsa:2048 -keyout "$name.key" -out "$name.csr" \
        -nodes -subj "/CN=picoquic sni test $name"
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key \
        -out "$name.crt" -days "$DAYS" -set_serial "0x$(openssl rand -hex 8)" \
        -extfile /dev/stdin <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
    rm "$name.csr"
}

gen_leaf default "DNS:default.example.com"
gen_leaf alpha "DNS:alpha.example.com"
gen_leaf beta "DNS:beta.example.com,DNS:*.wild.example.com"
gen_client client
