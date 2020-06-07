#!/bin/bash
# Checks that versions of the DPDK library compile successfully
# Ensure that all DPDK requirements are installed on the system

echo
echo "Note the system package of DPDK sometimes might take priority"
echo "over these static builds. The resulting error looks like this:"
echo "/usr/bin/ld: .libs/libtrace.so.4.1.5: version node not found for symbol rte_lpm6_add@DPDK_2.0"
echo "/usr/bin/ld: failed to set dynamic section sizes: bad value"
echo

TEST_DIR=$(pwd)
LIBTRACE_DIR="$TEST_DIR"/../
DPDK_DOWNLOAD_PATH=https://wand.nz/~rsanger/dpdk/
DOWNLOAD_DIR="$TEST_DIR"/DPDK_source
BUILD_DIR="$TEST_DIR"/DPDK_builds
BUILD_THREADS=9


SUCCESSFUL=""
DPDK_FAILED=""
LIBTRACE_FAILED=""
OK=0
FAIL=""
ERROR_MSG=""

do_test() {
	"$@"
	ret=$?
	if [ $ret = 0 ]; then
		OK=$[ $OK + 1]
		return $ret
	else
		FAIL="$FAIL
$ERROR_MSG ($@)"
		return $ret
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

# Versions to check buster linux 4.19
# A full list of DPDK versions to check in buster
declare -a dpdk_versions=(
	"dpdk-16.11.11.tar.gz"
	"dpdk-17.05.2.tar.gz"
	"dpdk-17.08.2.tar.gz"
	"dpdk-17.11.10.tar.gz"
	"dpdk-18.02.2.tar.gz"
	"dpdk-18.05.1.tar.gz"
	"dpdk-18.08.1.tar.gz"
	"dpdk-18.11.7.tar.gz"
	"dpdk-19.02.tar.gz"
	"dpdk-19.05.tar.gz"
	"dpdk-19.08.2.tar.gz"
	"dpdk-19.11.1.tar.gz"
	"dpdk-20.02.tar.gz"
	)

# Versions to check buster linux 4.19
# Main LTS releases to check in buster
declare -a dpdk_versions=(
	"dpdk-16.11.11.tar.gz"
	"dpdk-17.11.10.tar.gz"
	"dpdk-18.11.7.tar.gz"
	"dpdk-19.11.1.tar.gz"
	"dpdk-20.02.tar.gz"
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
			DPDK_FAILED="$DPDK_FAILED
Failed to download $dpdk_version"
		else
			tar xf "$dpdk_version"
			if [ $? -ne 0 ]; then
				echo "ERROR: Failed to extract" "$dpdk_version"
				DPDK_FAILED="$DPDK_FAILED
Failed to extract $dpdk_version"
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
	if [ -f build_success ]; then
		echo "	Already built - skipping"
		cd ..
		continue
	fi
	ERROR_MSG="Building $dpdk_build"
	do_test make install T=x86_64-native-linuxapp-gcc \
		             CONFIG_RTE_BUILD_COMBINE_LIBS=y \
			     CONFIG_RTE_LIBRTE_KNI=n \
			     CONFIG_RTE_KNI_KMOD=n \
			     CONFIG_RTE_LIBRTE_PMD_PCAP=y \
			     EXTRA_CFLAGS="-fPIC -w -ggdb" -j $BUILD_THREADS \
			     > build_stdout.txt 2> build_stderr.txt
	if [ $? = 0 ]; then
		touch build_success
		echo "	Built successfully"
	else
		rm build_success > /dev/null 2>&1
		echo "	Build Failed"
		DPDK_FAILED="$DPDK_FAILED
Failed to build $dpdk_version"
	fi
	cd ..
done

rm -r "$BUILD_DIR" > /dev/null
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
	# Skip any failed DPDK builds
	if [ ! -f "$DOWNLOAD_DIR"/"$dpdk_build"/build_success ]; then
		continue
	fi
	echo "Building libtrace with $dpdk_build - this may take some time"
	export RTE_SDK="$DOWNLOAD_DIR"/"$dpdk_build"
	export RTE_TARGET=x86_64-native-linuxapp-gcc

	make clean > /dev/null 2> /dev/null
	OUTPUT_PREFIX="$BUILD_DIR"/"$dpdk_build" 
	rm -r "$OUTPUT_PREFIX" > /dev/null 2> /dev/null
	mkdir "$OUTPUT_PREFIX"
	if [ ! -d "$OUTPUT_PREFIX" ]; then
		echo "	ERROR: Could not create libtrace build directory $dpdk_build"
		continue
	fi
	./bootstrap.sh > /dev/null 2> /dev/null
	ERROR_MSG="Building libtrace against $dpdk_build"
	do_test ./configure --with-dpdk --prefix="$OUTPUT_PREFIX" \
		> "$OUTPUT_PREFIX"/conf_out.txt 2> "$OUTPUT_PREFIX"/conf_err.txt
	if [ $? -ne 0 ]; then
		LIBTRACE_FAILED="$LIBTRACE_FAILED
./configure for libtrace failed against $dpdk_build
	Are you missing dependencies or do you need to run bootstrap.sh?
	check ${OUTPUT_PREFIX}conf_err.txt"
		continue
	fi
	echo -n "	"
	do_test grep "configure: Compiled with DPDK live capture support: Yes" \
	             "$OUTPUT_PREFIX"/conf_out.txt  
	if [ $? -ne 0 ]; then
		LIBTRACE_FAILED="$LIBTRACE_FAILED
./configure for libtrace did not detect dpdk $dpdk_build
	check ${OUTPUT_PREFIX}conf_err.txt"
		continue
	fi
	do_test make EXTRA_CFLAGS="-ggdb" -j $BUILD_THREADS \
		> "$OUTPUT_PREFIX"/make_out.txt 2> "$OUTPUT_PREFIX"/make_err.txt
	if [ $? -ne 0 ]; then
		LIBTRACE_FAILED="$LIBTRACE_FAILED
$dpdk_build Building libtrace failed (make)
	check ${OUTPUT_PREFIX}make_err.txt"
		continue
	fi
	do_test make install \
		> "$OUTPUT_PREFIX"/install_out.txt 2> "$OUTPUT_PREFIX"/install_err.txt
	if [ $? -ne 0 ]; then
		LIBTRACE_FAILED="$LIBTRACE_FAILED
$dpdk_build Installing libtrace failed (make install)
	check ${OUTPUT_PREFIX}install_err.txt"
		continue
	fi

	if [ ! -f "$OUTPUT_PREFIX"/bin/tracepktdump ]; then
		LIBTRACE_FAILED="$LIBTRACE_FAILED
$dpdk_build Unexpected the build succeeded but tracepktdump is missing"
		continue
	fi

	cd "$OUTPUT_PREFIX"/bin

	echo -n "	"
	./tracepktdump -H | grep "dpdk format module"
	if [ $? -ne 0 ]; then
		LIBTRACE_FAILED="$LIBTRACE_FAILED
$dpdk_build Unexpected the build succeeded but tracepktdump does not accept the dpdk format"
	else
		SUCCESSFUL="$SUCCESSFUL
$dpdk_build"
	fi
done

echo
echo "### Tests passed: $OK"
echo
echo "### Tests failed: $FAIL"
echo
echo "### Successfully built libtrace against the following versions of DPDK: $SUCCESSFUL"
echo
echo "### Failed to build or download these versions of DPDK: $DPDK_FAILED"
echo
echo "### Failed to build libtrace against the following versions of DPDK: $LIBTRACE_FAILED"
echo
if [ "$FAIL" != "" ]; then
	echo "Some tests failed check the output logs"\
	     "conf/make/install[_err/_out].txt" \
	     "in the build directory"
fi
