#!/bin/bash
# Checks that versions of the DPDK library compile successfully
# Ensure that all DPDK requirements are installed on the system

echo
echo "Note the system package of DPDK sometimes might take priority"
echo "over these static builds. The resulting error looks like this:"
echo "/usr/bin/ld: .libs/libtrace.so.4.1.5: version node not found for symbol rte_lpm6_add@DPDK_2.0"
echo "/usr/bin/ld: failed to set dynamic section sizes: bad value"
echo

if ! command -v meson &> /dev/null
then
	echo "meson not found, it is required for DPDK 20.11 and newer"
	echo "please install using 'apt install meson'"
	read -p "Press enter to continue"
	echo
fi

TEST_DIR=$(pwd)
LIBTRACE_DIR="$TEST_DIR"/../
DPDK_DOWNLOAD_PATH=https://libtraceteam.github.io/dpdk-testing/srcs
DOWNLOAD_DIR="$TEST_DIR"/DPDK_source
BUILD_DIR="$TEST_DIR"/DPDK_builds

if command -v nproc &> /dev/null
then
	BUILD_THREADS=$(( $(nproc)+1 ))
else
	BUILD_THREADS=9
fi
echo "Using $BUILD_THREADS build threads"


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
		OK=$(( OK + 1))
		return $ret
	else
		FAIL="$FAIL
$ERROR_MSG ($*)"
		return $ret
	fi
}

while [[ $# -gt 0 ]]; do
	dpdk_versions=()
        key="$1"
        case $key in
        dpdk-16.11.11|dpdk-17.11.10|dpdk-18.11.11|dpdk-19.11.13|dpdk-20.11.6|dpdk-21.11.2|dpdk-22.07|dpdk-23.11)
		dpdk_versions+=("$key.tar.xz")
		;;
	*)
                echo "Unknown version: $key"
        esac
        shift
done

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
			tar xJf "$dpdk_version"
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
#   - excluding it also makes the build faster
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
	# Prefer building with make if available otherwise use meson
	if [ -e ./GNUmakefile ]; then
		echo "	Building using Make"
		do_test make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
		DPDK_CONFIG=./x86_64-native-linuxapp-gcc/.config
		if [ -f "$DPDK_CONFIG" ]; then
			echo "CONFIG_RTE_BUILD_COMBINE_LIBS=y" >> "$DPDK_CONFIG"
			echo "CONFIG_RTE_LIBRTE_KNI=n" >> "$DPDK_CONFIG"
			echo "CONFIG_RTE_KNI_KMOD=n" >> "$DPDK_CONFIG"
			echo "CONFIG_RTE_LIBRTE_PMD_PCAP=y" >> "$DPDK_CONFIG"
			echo "CONFIG_RTE_EAL_IGB_UIO=n" >> "$DPDK_CONFIG"
			do_test make install T=x86_64-native-linuxapp-gcc \
                                             DESTDIR=/usr/local/ \
					     EXTRA_CFLAGS="-fcommon -fPIC -w -ggdb" -j $BUILD_THREADS \
					     > build_stdout.txt 2> build_stderr.txt
			ret=$?
		else
			ret=1
		fi
	else
		echo "	Building using meson"
		mkdir install
                cat << "EOF" > $(pwd)/drivers/net/meson.build
drivers = [
        'af_packet',
        'pcap',
        'null',
        'vhost',
        'virtio',
]
std_deps = ['ethdev', 'kvargs'] # 'ethdev' also pulls in mbuf, net, eal etc
std_deps += ['bus_pci']         # very many PMDs depend on PCI, so make std
std_deps += ['bus_vdev']        # same with vdev bus
config_flag_fmt = 'RTE_LIBRTE_@0@_PMD'  # required for 20.11.6 only
EOF

		if CFLAGS="-fcommon -ggdb3 -w" do_test meson \
                            --prefix=$(pwd)/install build \
                            -Ddisable_drivers=baseband/*,compress/*,crypto/*,dma/*,event/*,gpu/*,raw/*,regex/*,vdpa/* \
				> build_stdout.txt 2> build_stderr.txt ; then
			cd ./build
			CFLAGS="-fcommon -ggdb3 -w" do_test meson install > ../build_stdout.txt 2> ../build_stderr.txt
			ret=$?
			cd ..
		else
			ret=$?
		fi
	fi
	if [ "$ret" = 0 ]; then
		touch build_success
		echo "	Built successfully"
	else
		rm build_success > /dev/null 2>&1
		echo "	Build Failed"
		DPDK_FAILED="$DPDK_FAILED
Failed to build $dpdk_build
	check $(pwd)/build_stderr.txt"
                cat $(pwd)/build_stderr.txt
                echo
                cat $(pwd)/build_stdout.txt
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
	do_test ./configure --with-dpdk --prefix="$OUTPUT_PREFIX" CFLAGS="-ggdb" \
		> "$OUTPUT_PREFIX"/conf_out.txt 2> "$OUTPUT_PREFIX"/conf_err.txt
	if [ $? -ne 0 ]; then
		LIBTRACE_FAILED="$LIBTRACE_FAILED
./configure for libtrace failed against $dpdk_build
	Are you missing dependencies or do you need to run bootstrap.sh?
	check ${OUTPUT_PREFIX}conf_err.txt"
                cat ${OUTPUT_PREFIX}conf_err.txt
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
	do_test make -j $BUILD_THREADS \
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
