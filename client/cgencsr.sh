#!/bin/bash

echo "client name:"
echo $1
ts=$(date +%s.%N)
echo $ts

openssl genrsa -out client_files/key.pem 2048
chmod 400 client_files/key.pem

openssl req -config ../ca/intermediate/openssl.cnf \
      -key client_files/key.pem \
      -new -sha256 -out client_files/csr.pem \
      -subj "/C=US/ST=California/L=LA/O=$1/OU=$1.$ts/CN=$1"
