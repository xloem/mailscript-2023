#!/usr/bin/env bash

HOST=localhost
IP=127.0.0.1

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 99999 \
  -nodes -keyout "$HOST".key -out "$HOST".pem -subj "/CN=$HOST" \
  -addext "subjectAltName=DNS:$HOST,DNS:*.$HOST,IP:$IP"
chmod 0400 "$HOST".key
chmod 0444 "$HOST".pem
