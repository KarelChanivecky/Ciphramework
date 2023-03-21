#!/bin/bash

#these variables intentionally are not wrapped in quotes
cipher=${xor:-$1}
cipher_args=$2
mode=$3
mode_args=$4
mode=${mode:+"-d $mode"}

echo CIPHER=$cipher
echo CIPHER_ARGS=$cipher_args
echo MODE=$mode
echo MODE_ARGS=$mode_args

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

function wait_on_error() {
    echo "$1"
    read
    echo -en "\033[1A\033[2K"
}

for key_path in "${key_paths[@]}"; do
    for plaintext_path in "${plaintext_paths[@]}"; do
        ((index++))
        key_name="$(basename "${key_path}")"
        plaintext_name="$(basename "${plaintext_path}")"
        cipher_path="./encrypted/$plaintext_name-$key_name.kcrypt"
        decrypted_path="./decrypted/$plaintext_name"
        echo "$index/$total_tests testing plaintext, key combination: $plaintext_name, $key_name"
        $EXE $cipher -p e -l "$key_path" $mode -f "$plaintext_path" -o "$cipher_path" $cipher_args $mode_args
        ret=$?
        if [ $ret -ne 0 ]; then
            ((failed_tests++))
            wait_on_error "TEST FAILED: encryption failed: $ret"
            continue
        fi

        $EXE $cipher -p d -l "$key_path" $mode -f "$cipher_path" -o "$decrypted_path" $cipher_args $mode_args
        ret=$?
        if [ $ret -ne 0 ]; then
            ((failed_tests++))

            wait_on_error "TEST FAILED: decryption failed: $ret"
            continue
        fi

        # using cat to suppress output of filenames by sha
        plaintext_sha=$(cat "$plaintext_path" | sha256sum -b)
        decrypted_sha=$(cat "$decrypted_path" | sha256sum -b)

        if [ "$decrypted_sha" = "$plaintext_sha" ]; then
            echo "TEST PASSED: $plaintext_sha == $decrypted_sha"
        else
            ((failed_tests++))
            wait_on_error "TEST FAILED: Decrypted != plaintext: $plaintext_sha == $decrypted_sha"
        fi
    done
done

echo "Failed tests count: $failed_tests"
