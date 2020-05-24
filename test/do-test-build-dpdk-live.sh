#!/bin/bash
# Run after ./do-test-build-dpdk
# Checks that versions of the DPDK library compile successfully
# Ensure that all DPDK requirements are installed on the system

TEST_DIR=$(pwd)
LIBTRACE_DIR="$TEST_DIR"/../
DOWNLOAD_DIR="$TEST_DIR"/DPDK_source
BUILD_DIR="$TEST_DIR"/DPDK_builds

cd "$BUILD_DIR"
for dpdk_build in $(ls -d */)
do
	echo "$dpdk_build"
	cd "$TEST_DIR"
	export LD_LIBRARY_PATH="$BUILD_DIR/$dpdk_build/lib"
	./do-live-tests.sh
done
