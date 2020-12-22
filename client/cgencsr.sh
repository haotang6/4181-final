#!/bin/bash

echo "client name:"
echo $1

openssl genrsa -out $1.key.pem 2048
chmod 400 $1.key.pem

openssl req -config ../ca/intermediate/openssl.cnf \
      -key $1.key.pem \
      -new -sha256 -out $1.csr.pem \
      -subj "/C=US/ST=California/L=LA/O=$1/OU=$1$(date '+%s')/CN=$1"
