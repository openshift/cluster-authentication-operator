#!/bin/bash
set -e

PASSWORD=${PASSWORD:-password}
DIR="$( dirname "${BASH_SOURCE[0]}")"

function create_ca() {
    # gen cert/key pair for CA, use password to secure the key because why not
    openssl genrsa -aes256 -passout "pass:$PASSWORD" -out "${DIR}/rootCA.key" 4096
    openssl req -x509 -new -nodes -key "${DIR}/rootCA.key" \
        -sha512 -days 3655 -out "${DIR}/rootCA.crt" \
        -subj "/C=CZ/ST=Moravia/O=My Private Org Ltd./CN=Test CA" \
        -extensions v3_ca -config "${DIR}/custom.cnf" \
        -passin "pass:${PASSWORD}"
}

function create_client() {
    # generate cert/key pair for client auth, let's omit password for simplicity of use
    openssl genrsa -out "${DIR}/client.key" 4096
    openssl req -new -sha256 -key "${DIR}/client.key" \
        -subj "/C=CZ/ST=Moravia/O=My Private Org Ltd./CN=somewhere.com" \
        -out "${DIR}/client.csr"

    openssl x509 -req -in "${DIR}/client.csr" -CA "${DIR}/rootCA.crt" \
        -CAkey "${DIR}/rootCA.key" -CAcreateserial -out "${DIR}/client.crt" \
        -days 1024 -sha256 -extfile "${DIR}/custom.cnf" -extensions client_auth \
        -passin "pass:${PASSWORD}"
}

function config_requestheader_idp() {
    create_ca
    create_client

    oc create cm request-header-ca --from-file="ca.crt=${DIR}/rootCA.crt" -n openshift-config
    oc apply -f "${DIR}/requestheaderidp.yaml"
}

config_requestheader_idp
