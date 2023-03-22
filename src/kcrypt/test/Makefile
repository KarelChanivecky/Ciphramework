CIPHER := ${CIPHER}
CIPHER_ARGS := ${CIPHER_ARGS}
MODE := ${MODE}
MODE_ARGS := ${MODE_ARGS}
BUILD_TYPE := ${BUILD_TYPE}
ROUND_KEYS := ${ROUND_KEYS}

.PHONY: force_clean_test_results
force_clean_test_results: FORCE
	rm -rdf ./decrypted/**
	rm -rdf ./encrypted/**

.PHONY: clean_test_results
clean_test_results:
	rm -rdf ./decrypted/**
	rm -rdf ./encrypted/**

.PHONY: clean
clean: clean_test_results
	make -C ./build clean || echo No need to clean build dir

.PHONY: kcrypt
kcrypt: FORCE
	./build_exe.sh ${BUILD_TYPE}

.PHONY: debug
debug: FORCE
	./build_exe.sh CPLIB_DEBUG

.PHONY: verbose
verbose: FORCE
	./build_exe.sh CPLIB_VERBOSE

.PHONY: mem
mem: FORCE
	./build_exe.sh CPLIB_LOG_MEM

.PHONY: clean_n_build
clean_n_build: clean kcrypt

.PHONY:test_xor_ecb
test_xor_ecb: force_clean_test_results kcrypt
	./test.sh xor

.PHONY: test_xor_cbc
test_xor_cbc: force_clean_test_results kcrypt
	./test.sh xor "-- CIPHER" CBC "-- MODE -f ./iv/binary-32b-2314643986.txt"

.PHONY: test_xor_ctr
test_xor_ctr: force_clean_test_results kcrypt
	./test.sh xor "-- CIPHER" CTR "-- MODE -f ./iv/binary-64b-16891392968528426633.txt -c 1"

.PHONY: test_xor
test_xor: test_xor_ctr test_xor_cbc test_xor_ecb

.PHONY: test_feisty.no_round_key_ecb
test_feisty.no_round_key_ecb: force_clean_test_results kcrypt
	./test.sh feisty.no_round_key

.PHONY:test_feisty.no_round_key_cbc
test_feisty.no_round_key_cbc: force_clean_test_results kcrypt
	./test.sh feisty.no_round_key "-- CIPHER" CBC "-- MODE -f ./iv/binary-64b-16891392968528426633.txt"

.PHONY: test_feisty.no_round_key_ctr
test_feisty.no_round_key_ctr: force_clean_test_results kcrypt
	./test.sh feisty.no_round_key "-- CIPHER" CTR "-- MODE -f ./iv/binary-64b-16891392968528426633.txt -c 1"

.PHONY: test_feisty.no_round_key
test_feisty.no_round_key: test_feisty.no_round_key_ecb test_feisty.no_round_key_ctr test_feisty.no_round_key_cbc

.PHONY: test_feisty.configurable_round_key_ecb_def_rkey 
test_feisty.configurable_round_key_ecb_def_rkey: force_clean_test_results kcrypt
	./test.sh feisty.configurable_round_key "-- CIPHER -d"

.PHONY: test_feisty.configurable_round_key_cbc_def_rkey
test_feisty.configurable_round_key_cbc_def_rkey: force_clean_test_results kcrypt
	./test.sh feisty.configurable_round_key "-- CIPHER -d" CBC "-- MODE -f ./iv/binary-64b-16891392968528426633.txt"

.PHONY: test_feisty.configurable_round_key_ctr_def_rkey
test_feisty.configurable_round_key_ctr_def_rkey: force_clean_test_results kcrypt
	./test.sh feisty.configurable_round_key "-- CIPHER -d" CTR "-- MODE -f ./iv/binary-64b-16891392968528426633.txt -c 1"

.PHONY: test_feisty.configurable_round_key_def_rkey
test_feisty.configurable_round_key_def_rkey: test_feisty.configurable_round_key_ecb_def_rkey test_feisty.configurable_round_key_ctr_def_rkey test_feisty.configurable_round_key_cbc_def_rkey

.PHONY: test_feisty.configurable_round_key_given_ecb
test_feisty.configurable_round_key_given_ecb: force_clean_test_results kcrypt
	./test.sh feisty.configurable_round_key "-- CIPHER -r ${ROUND_KEYS}"

.PHONY: test_feisty.configurable_round_key_given_cbc
test_feisty.configurable_round_key_given_cbc: force_clean_test_results kcrypt
	./test.sh feisty.configurable_round_key "-- CIPHER -r ${ROUND_KEYS}" CBC "-- MODE -f ./iv/binary-64b-16891392968528426633.txt"

.PHONY: test_feisty.configurable_round_key_given_ctr
test_feisty.configurable_round_key_given_ctr: force_clean_test_results kcrypt
	./test.sh feisty.configurable_round_key "-- CIPHER  -r ${ROUND_KEYS}" CTR "-- MODE -f ./iv/binary-64b-16891392968528426633.txt -c 1"

.PHONY: test_feisty.configurable_round_key_given
test_feisty.configurable_round_key_given: test_feisty.configurable_round_key_given_ecb test_feisty.configurable_round_key_given_ctr test_feisty.configurable_round_key_given_cbc


.PHONY: test_feisty.configurable_round_key_ecb
test_feisty.configurable_round_key_ecb: force_clean_test_results kcrypt
	./test.sh feisty.configurable_round_key

.PHONY: test_feisty.configurable_round_key_cbc
test_feisty.configurable_round_key_cbc: force_clean_test_results kcrypt
	./test.sh feisty.configurable_round_key "-- CIPHER" CBC "-- MODE -f ./iv/binary-64b-16891392968528426633.txt"

.PHONY: test_feisty.configurable_round_key_ctr
test_feisty.configurable_round_key_ctr: force_clean_test_results kcrypt
	./test.sh feisty.configurable_round_key "-- CIPHER" CTR "-- MODE -f ./iv/binary-64b-16891392968528426633.txt -c 1"

.PHONY: test_feisty.configurable_round_key
test_feisty.configurable_round_key: test_feisty.configurable_round_key_ecb test_feisty.configurable_round_key_ctr test_feisty.configurable_round_key_cbc

.PHONY: test_all
test_all: test_xor test_feisty.no_round_key test_feisty.configurable_round_key test_feisty.configurable_round_key_def_rkey test_feisty.configurable_round_key_given

.PHONY: test_custom
test_custom: clean_n_build
	./test.sh ${CIPHER} ${CIPHER_ARGS} ${MODE} ${MODE_ARGS}


# Force rule to run by using as dependency
FORCE: