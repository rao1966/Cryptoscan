#!/bin/bash

# CryptoScan L3 controlled test
openssl enc -aes-256-cbc -in input.txt -out encrypted.dat
openssl dgst -sha1 input.txt
ssh-keygen -t rsa -b 2048 -f test_rsa_key