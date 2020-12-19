#!/bin/bash
# ./cgenkeypair.sh <client_name>

openssl genrsa -out $1.key.pem 2048
openssl rsa -in $1.key.pem -pubout -out $1.pubkey.pem