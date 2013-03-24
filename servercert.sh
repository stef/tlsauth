#!/usr/bin/env bash

openssl genrsa -out "$1".key 4096
tmpconf=$(mktemp)
cat >$tmpconf <<EOF
[ req ]
default_bits            = 4096
default_md              = sha512
distinguished_name      = req_distinguished_name

[ req_distinguished_name ]
commonName                     = Common Name (eg, server FQDN)
commonName_max                 = 64

emailAddress                   = Email Address
emailAddress_max               = 64
EOF
trap "rm -f $tmpconf" 0 1 2 3 15
openssl req -new -key "$1".key -out "$1".csr -config $tmpconf
echo "sign this with cd <root-ca>; signcert.sh ../$1 ; cd -"
