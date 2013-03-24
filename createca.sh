#!/usr/bin/env bash

# 1st param: folder name of new ca
# 2nd param: cert revocation list location uri
name=${1:-root-ca}

mkdir -p $name/{signed-keys,conf,private,public,incoming}
cd $name
chmod 700 private

cat >conf/openssl.conf <<EOF
[ req ]
default_bits            = 4096
default_keyfile         = ./private/root.pem
default_md              = sha512
distinguished_name      = root_ca_distinguished_name
x509_extensions = v3_ca

[ root_ca_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = HU
countryName_min                 = 2
countryName_max                 = 2

0.organizationName              = Root CA Organization Name (eg, company)

commonName                      = Common Name (server FQDN)
commonName_max                  = 64

emailAddress                    = Email Address
emailAddress_max                = 64

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true

[ ca ]
default_ca              = CA_default

[ CA_default ]
dir                     = .
new_certs_dir           = ./signed-keys/
database                = ./conf/index
certificate             = ./public/root.pem
serial                  = ./conf/serial
private_key             = ./private/root.pem
x509_extensions         = usr_cert
name_opt                = ca_default
cert_opt                = ca_default
default_crl_days        = 30
default_days            = 365
default_md              = sha512
preserve                = no
policy                  = policy_match

[ policy_match ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ usr_cert ]
basicConstraints=CA:FALSE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always
nsCaRevocationUrl     = $2

EOF
openssl req -nodes -config conf/openssl.conf -days 1825 -x509 -newkey rsa:4096 -out public/root.pem -outform PEM
echo "01" > conf/serial
touch conf/index

# create dummy.pem for pytlsauth
dummy.sh
cd -
