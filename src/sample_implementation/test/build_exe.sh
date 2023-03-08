#!/bin/bash

EXECUTABLE=kcrypt
BUILD_TYPE=${1:-CPLIB_RELEASE}

mkdir -p ./build


cmake -DCMAKE_BUILD_TYPE=Debug -D BUILD_TYPE=$BUILD_TYPE -S ../../../ -B ./build

pushd build || exit 1

cmake --build .

popd || exit 1


