#!/bin/bash
set -e

DIR="$( dirname "${BASH_SOURCE[0]}")"

REMOTE_USER="${REMOTE_USER:-randomuser}"
AUTH_ENDPOINT="$(oc get --raw /.well-known/oauth-authorization-server | jq '.authorization_endpoint' | tr -d '\"')"

curl -s -k -I -H "X-Remote-User: $REMOTE_USER"  --cert "${DIR}/client.crt" --key "${DIR}/client.key" "${AUTH_ENDPOINT}?client_id=openshift-challenging-client&response_type=token" | grep "Location" | sed -e 's/.*access_token\=\([^&]*\).*/\1/' 
