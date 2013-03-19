#!/usr/bin/env bash

conf=${2:-conf/openssl.conf}
echo $conf
openssl ca -batch -config "$conf" -in "$1".csr -out "$1".cert
