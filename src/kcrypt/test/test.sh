#!/bin/bash

set -o pipefail

EXE=./build/kcrypt

mkdir -p encrypted
mkdir -p decrypted

key_paths=($(ls key/*))
plaintext_paths=($(ls plaintext/*))
failed_tests=0

index=0
key_count="(${#key_paths[@]})"
pt_count="(${#plaintext_paths[@]})"

echo "number of keys: $key_count"
echo "number of plaintexts: $pt_count"

let total_tests=$((key_count * pt_count))

echo total_tests: $total_tests

for key_path in "${key_paths[@]}"; do
  for plaintext_path in "${plaintext_paths[@]}"; do
    ((index++))
    key_name="$(basename "${key_path}")"
    plaintext_name="$(basename "${plaintext_path}")"
    cipher_path="./encrypted/$plaintext_name-$key_name.kcrypt"
    decrypted_path="./decrypted/$plaintext_name"
    echo "$index/$total_tests testing plaintext, key combination: $plaintext_name, $key_name"
    $EXE feisty -p e -l $key_path -f $plaintext_path -o $cipher_path
    if [ $? -ne 0 ]
    then
       echo "TEST FAILED: encryption failed"
       ((failed_tests++))
       continue
    fi

    $EXE feisty -p d -l $key_path -f $cipher_path -o $decrypted_path
    if [ $? -ne 0 ]
    then
      echo "TEST FAILED: decryption failed"
      ((failed_tests++))
      continue
    fi

    plaintext_sha=$(cat $plaintext_path | sha256sum -b)
    decrypted_sha=$(cat $decrypted_path | sha256sum -b)

    if [ "$decrypted_sha" = "$plaintext_sha" ]
    then
      echo "TEST PASSED: $plaintext_sha == $decrypted_sha"
    else
      echo "TEST FAILED: Decrypted != plaintext: $plaintext_sha == $decrypted_sha"
      read
      ((failed_tests++))
    fi
  done
done

echo "Failed tests count: $failed_tests"

