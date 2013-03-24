#!/usr/bin/env bash

# generate dummy for pytlsauth
openssl genrsa -out dummy.key 1024
tmpconf=$(mktemp)
cat >$tmpconf <<EOF
[ req ]
default_bits            = 4096
default_md              = sha512
distinguished_name      = req_distinguished_name
prompt                  = no

[ req_distinguished_name ]
commonName                     = Common Name (eg, YOUR name)
emailAddress                   = Email Address
EOF
trap "rm -f $tmpconf" 0 1 2 3 15

openssl req -new -key dummy.key -out dummy.csr -config $tmpconf
openssl ca -batch -config conf/openssl.conf -in dummy.csr -out dummy.pem
rm dummy.csr dummy.key
