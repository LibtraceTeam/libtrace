#!/bin/bash
# Checks that versions of the DPDK library compile successfully
# Ensure that all DPDK requirements are installed on the system

TEST_DIR=$(pwd)
LIBTRACE_DIR="$TEST_DIR"/../
DPDK_DOWNLOAD_PATH=http://wand.nz/~rjs51/dpdk/
DOWNLOAD_DIR="$TEST_DIR"/DPDK_source
BUILD_DIR="$TEST_DIR"/DPDK_builds
BUILD_THREADS=9


OK=0
FAIL=""

do_test() {
	if "$@"; then
		OK=$[ $OK + 1]
	else
		FAIL="$FAIL
$@"
	fi
}

# Old kernel version jessie 3.16
declare -a dpdk_versions=(
	"dpdk-1.7.1.tar.gz"
	"dpdk-1.8.0.tar.gz"
	"dpdk-2.0.0.tar.gz"
	"dpdk-2.1.0.tar.gz"
	"dpdk-2.2.0.tar.gz"
	"dpdk-16.04.tar.gz"
	"dpdk-16.07.2.tar.gz"
	"dpdk-16.11.6.tar.gz"
	)
# Versions to check stretch linux 4.9
declare -a dpdk_versions=(
	"dpdk-2.2.0.tar.gz"
	"dpdk-16.04.tar.gz"
	"dpdk-16.07.2.tar.gz"
	"dpdk-16.11.6.tar.gz"
	"dpdk-17.02.1.tar.gz"
	"dpdk-17.05.2.tar.gz"
	"dpdk-17.08.2.tar.gz"
	"dpdk-17.11.2.tar.gz"
	"dpdk-18.02.1.tar.gz"
	)


mkdir "$DOWNLOAD_DIR" > /dev/null 2>&1
if [ ! -d "$DOWNLOAD_DIR" ]; then
	echo "ERROR: Could not create download directory"
	return 1
fi
cd "$DOWNLOAD_DIR"

# Download versions of DPDK
for dpdk_version in "${dpdk_versions[@]}"
do
	if [ ! -e "$dpdk_version" ]; then
		wget "$DPDK_DOWNLOAD_PATH"/"$dpdk_version" > /dev/null
		if [ $? -ne 0 ]; then
			echo "ERROR: Failed to download" "$dpdk_version"
		else
			tar xf "$dpdk_version"
			if [ $? -ne 0 ]; then
				echo "ERROR: Failed to extract" "$dpdk_version"
			fi
		fi
	fi
done

# Build the DPDK libraries
# We try to not overwrite these, so that a rebuild is faster
# We build DPDK without KNI, as most kernel dependent code is there
#   - also excluding makes the build faster
# We also disable error on warning, to improve forwards compiler compatibility
cd "$DOWNLOAD_DIR"
for dpdk_build in $(ls -d */)
do
	cd "$dpdk_build"
	echo "Building $dpdk_build - this might take some time"
	do_test make install T=x86_64-native-linuxapp-gcc \
		             CONFIG_RTE_BUILD_COMBINE_LIBS=y \
			     CONFIG_RTE_LIBRTE_KNI=n \
			     CONFIG_RTE_KNI_KMOD=n \
			     EXTRA_CFLAGS="-fPIC -w" -j $BUILD_THREADS \
			     > build_stdout.txt 2> build_stderr.txt
	cd ..
done

rm -r "$BUILD_DIR" > /dev/null 2>&1
mkdir "$BUILD_DIR"
if [ ! -d "$BUILD_DIR" ]; then
	echo "ERROR: Could not create build directory"
	return 1
fi

# Build libtrace against each version
cd "$DOWNLOAD_DIR"
for dpdk_build in $(ls -d */)
do
	cd "$LIBTRACE_DIR"
	echo "Building libtrace with $dpdk_build - this may take some time"
	export RTE_SDK="$DOWNLOAD_DIR"/"$dpdk_build"
	export RTE_TARGET=x86_64-native-linuxapp-gcc

	make clean > /dev/null 2> /dev/null
	OUTPUT_PREFIX="$BUILD_DIR"/"$dpdk_build" 
	rm -r "$OUTPUT_PREFIX" > /dev/null 2> /dev/null
	mkdir "$OUTPUT_PREFIX"
	if [ ! -d "$OUTPUT_PREFIX" ]; then
		echo "ERROR: Could not create libtrace build directory $dpdk_build"
		continue
	fi
	./bootstrap.sh > /dev/null 2> /dev/null
	do_test ./configure --with-dpdk --prefix="$OUTPUT_PREFIX" \
		> "$OUTPUT_PREFIX"/conf_out.txt 2> "$OUTPUT_PREFIX"/conf_err.txt
	do_test grep "configure: Compiled with DPDK live capture support: Yes" \
	             "$OUTPUT_PREFIX"/conf_out.txt  
	do_test make -j $BUILD_THREADS \
		> "$OUTPUT_PREFIX"/make_out.txt 2> "$OUTPUT_PREFIX"/make_err.txt
	do_test make install \
		> "$OUTPUT_PREFIX"/install_out.txt 2> "$OUTPUT_PREFIX"/install_err.txt
done

# Check we actually included dpdk
cd "$BUILD_DIR"
for dpdk_build in $(ls -d */)
do
	cd "$BUILD_DIR"/"$dpdk_build"/bin
	./tracepktdump -H | grep "dpdk format module"
	if [ $? -ne 0 ]; then
		FAIL="$FAIL
Failed to build $dpdk_build libtrace"
	fi
done

echo
echo "Tests passed: $OK"
echo "Tests failed: $FAIL"
if [ "$FAIL" != "" ]; then
	echo "Some tests failed check the output logs"\
	     "conf/make/install[_err/_out].txt" \
	     "in the build directory"
fi
