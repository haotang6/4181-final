#!/bin/bash

./cgettestcert.sh <client_name>

openssl req -config ../ca/intermediate/openssl.cnf \
      -key $1.key.pem \
      -new -sha256 -out ../ca/intermediate/csr/$1.csr.pem \
      -subj "/C=US/ST=California/L=LA/O=$1/OU=$1/CN=$1"

openssl ca -batch -config ../ca/intermediate/openssl.cnf \
      -extensions usr_cert -days 375 -notext -md sha256 \
      -passin pass:1234 \
      -in ../ca/intermediate/csr/$1.csr.pem \
      -out ../ca/intermediate/certs/$1.cert.pem \
      -subj "/C=US/ST=California/L=LA/O=$1/OU=$1/CN=$1"

cp ../ca/intermediate/certs/$1.cert.pem ./
