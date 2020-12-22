#!/bin/bash
# ./sgencert.sh <client_name> <csr_path>

echo "client name:"
echo $1
echo "csr path:"
echo $2

openssl ca -batch -config ../ca/intermediate/openssl.cnf \
      -extensions usr_cert -days 375 -notext -md sha256 \
      -passin pass:1234 \
      -in $2 \
      -out ../ca/intermediate/certs/$1.cert.pem
