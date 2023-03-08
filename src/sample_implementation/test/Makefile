default: test

kcrypt: FORCE
	./build_exe.sh CPLIB_DEBUG

clean:
	rm -rdf ./decrypted/**
	rm -rdf ./encrypted/**
	make -C ./build clean

test: clean kcrypt
	./test.sh

debug: FORCE
	./build_exe.sh CPLIB_DEBUG

verbose: FORCE
	./build_exe.sh CPLIB_VERBOSE

mem: FORCE
	./build_exe.sh CPLIB_LOG_MEM


FORCE:
