#!/usr/bin/env bash

conf=${2:-conf/openssl.conf}
echo $conf
openssl req -in "$1".csr -text -noout
openssl req -in "$1".csr -verify -noout
openssl req -noout -modulus -in "$1".csr | openssl sha1
echo press enter to continue or ^c to abort signing
read
openssl ca -batch -config "$conf" -in "$1".csr -out "$1".cert
{
    echo "Subject: Your $(openssl x509 -noout -issuer -in "$1".cert | sed 's/.*\/O=\([^/]*\).*/\1/') certificate"
    echo
    echo "Congrats, your certificate has been signed. It is copied below"
    echo "run this through cert2pkcs12.sh and then import it into your browser"
    echo "---------------- Cert Starts below ----------------"
    cat "$1".cert
} | cat ; echo "sendmail $(openssl req -in "$1".csr -subject -noout | sed 's/.*emailAddress=\(.*\)/\1/')"
