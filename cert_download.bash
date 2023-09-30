#!/usr/bin/env bash
for host in "$@"
do
    openssl s_client -connect "$host" </dev/null | openssl x509 > "${host%:*}".pem
    chmod 0444 "${host%:*}".pem
done
