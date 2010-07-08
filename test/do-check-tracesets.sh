#!/bin/bash

PREFIX=${1:-/trace/}
TEST=./test-convert2
export LD_LIBRARY_PATH=../lib/.libs:../libpacketdump/.libs
export LIBTRACEIO=directread

# Abilene 1
echo Testing Abilene I
for i in ${PREFIX}/pma/long/ipls/1/*.gz; do
	echo -n " * $i: "
	${TEST} legacypos:$i pcapfile && echo PASS
done

# Auckland I

# Auckland II
echo Testing Auckland II
for i in ${PREFIX}/auckland/2/*.gz; do
	echo -n " * $i: "
	${TEST} legacyatm:$i pcapfile && echo PASS
done

# Auckland IV
echo Testing Auckland IV
for i in ${PREFIX}/auckland/4/*.gz; do
	echo -n " * $i: "
	${TEST} legacyatm:$i pcapfile && echo PASS
done

# Auckland VI
echo Testing Auckland VI
for i in ${PREFIX}/auckland/6/*-[01].gz; do
	echo -n " * $i: "
	${TEST} legacyatm:$i pcapfile && echo PASS
done
for i in ${PREFIX}/auckland/6/*-e[01].gz; do
	echo -n " * $i: "
	${TEST} legacyeth:$i pcapfile && echo PASS
done

# Auckland VII
echo Testing Auckland VIII
for i in ${PREFIX}/auckland/8/*.gz; do
	echo -n " * $i: "
	${TEST} erf:$i pcapfile && echo PASS
done

# Leipzig I

# IPLS I (Abiline I?)

# Leipzig II

# NZIX II

# SDSC I

# Waikato I,II,II,IV
