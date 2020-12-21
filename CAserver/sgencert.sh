#!/bin/bash
# ./sgencert.sh <client_name> <csr_path>

echo "client name:"
echo $1
echo "csr path:"
echo $2

# ------------ this should be done on the client side -------------------
# openssl genrsa -out ~/ca/intermediate/private/georgia.key.pem 2048
# chmod 400 ~/ca/intermediate/private/georgia.key.pem

# openssl req -config ~/ca/intermediate/openssl.cnf \
#       -key ~/ca/intermediate/private/georgia.key.pem \
#       -new -sha256 -out ~/ca/intermediate/csr/georgia.csr.pem \
#       -subj "/C=US/ST=California/L=LA/O=georgia/OU=georgia/CN=georgia"
# -----------------------------------------------------------------------

openssl ca -batch -config ~/ca/intermediate/openssl.cnf \
      -extensions usr_cert -days 375 -notext -md sha256 \
      -passin pass:1234 \
      -in $2 \
      -out ~/ca/intermediate/certs/$1.cert.pem \
      -subj "/C=US/ST=California/L=LA/O='$1'/OU='$1'/CN='$1'"
