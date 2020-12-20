#!/bin/bash

openssl genrsa -out ../ca/intermediate/private/caserver.key.pem 2048
chmod 400 ../ca/intermediate/private/caserver.key.pem

openssl req -config ../ca/intermediate/openssl.cnf \
      -key ../ca/intermediate/private/caserver.key.pem \
      -new -sha256 -out ../ca/intermediate/csr/caserver.csr.pem \
      -subj "/CN=luckluckgo.com"

openssl ca -batch -config ../ca/intermediate/openssl.cnf \
      -extensions server_cert -days 375 -notext -md sha256 \
      -passin pass:1234 \
      -in ../ca/intermediate/csr/caserver.csr.pem \
      -out ../ca/intermediate/certs/caserver.cert.pem \
      -subj "/CN=luckluckgo.com"

cp ../ca/intermediate/private/caserver.key.pem ./
cp ../ca/intermediate/certs/caserver.cert.pem ./
