#!/usr/bin/env bash

# generate client cert
[[ -f $1.key ]] || openssl genrsa -out $1.key 4096
tmpconf=$(mktemp)
cat >$tmpconf <<EOF
[ req ]
default_bits            = 4096
default_md              = sha512
distinguished_name      = req_distinguished_name

[ req_distinguished_name ]
0.organizationName             = Organization Name (eg, your group, affiliation, if such)

commonName                     = Common Name (eg, YOUR name)
commonName_max                 = 64

emailAddress                   = Email Address
emailAddress_max               = 64

EOF
trap "rm -f $tmpconf" 0 1 2 3 15

echo openssl req -new -key $1.key -out $1.csr -config $tmpconf
openssl req -new -key "$1".key -out "$1".csr -config $tmpconf
echo send this to your CA for signing
cat "$1".csr
openssl rsa -noout -modulus -in "$1".key | openssl sha1
