#!/usr/bin/env bash

# creates a pkcs12 cert
# needs a certificate and a private key
echo pls enter your passphrase
#openssl pkcs12 -passout stdin -export -nokeys -cacerts -in $1.cert -out $1.cert.p12 -inkey $1.key || {
openssl pkcs12 -passout stdin -export -cacerts -in "$1".cert -out "$1".cert.p12 -inkey "$1".key || {
    echo 'error!'
    exit 1
}
echo import "$1".cert.p12 into your browser
echo backup "$1".key and "$1".cert in a safe place
