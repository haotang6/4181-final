#!/bin/bash

openssl genrsa -out ../ca/intermediate/private/mailserver.key.pem 2048
chmod 400 ../ca/intermediate/private/mailserver.key.pem

openssl req -config ../ca/intermediate/openssl.cnf \
      -key ../ca/intermediate/private/mailserver.key.pem \
      -new -sha256 -out ../ca/intermediate/csr/mailserver.csr.pem \
      -subj "/CN=duckduckgo.com"

openssl ca -batch -config ../ca/intermediate/openssl.cnf \
      -extensions server_cert -days 375 -notext -md sha256 \
      -passin pass:1234 \
      -in ../ca/intermediate/csr/mailserver.csr.pem \
      -out ../ca/intermediate/certs/mailserver.cert.pem \
      -subj "/CN=duckduckgo.com"


cp ../ca/intermediate/private/mailserver.key.pem ./
cp ../ca/intermediate/certs/mailserver.cert.pem ./
cp ../ca/intermediate/certs/ca-chain.cert.pem ./