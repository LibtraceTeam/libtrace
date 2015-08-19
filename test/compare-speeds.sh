#!/bin/sh

# A script that runs the single and multi threaded versions of libtrace programs
# Currently this compares tracestats and traceanon
# This requires a bit of environment setup since it requires large trace files
# 100mb+ ideally 1gb to ensure that the times are long enough to compare.
# See the defines block below for the environment expected

# outfilename
printresults() {
	WALLCLOCKAVG=$(cut -d , -f 2 $1 | tail -n +2 | awk '{a+=$1} END{print a/NR}')
	SYSAVG=$(cut -d , -f 3 $1 | tail -n +2 | awk '{a+=$1} END{print a/NR}')
	USERAVG=$(cut -d , -f 4 $1 | tail -n +2 | awk '{a+=$1} END{print a/NR}')
	echo "Wall=$WALLCLOCKAVG Sys=$SYSAVG User=$USERAVG STDOUTMATCH="
}


TRACES=$HOME/traces
LIBTRACE=$HOME/mylibtrace/
TRACESTATS=$LIBTRACE/tools/tracestats/tracestats
TRACESTATSP=$LIBTRACE/tools/tracestats/tracestats_parallel
TRACEANON=$LIBTRACE/tools/traceanon/traceanon
TRACEANONP=$LIBTRACE/tools/traceanon/traceanon_parallel
TRACESTATSARGS=
# Large output files are put here such as the output of traceanon, these files
# are not stored rather a md5sum is kept.
LARGEOUTPUT=/ramdisk
TRACEANONARGS=--encrypt-source --encrypt-dest --cryptopan="HereISS0meB1GKey"
# We push the most useful forward
TIMEFORMAT=%e,%S,%U,%C,%D,%F,%I,%K,%M,%O,%P,%R,%W,%X,%Z,%c,%k,%p,%r,%s,%t,%w,%x
CSVHEADINS="num,Wall Clock(e),System Time (S),User Time (U),Command (C),Average unshared data(D),Major page faults (F),I,K,M,O,P,R,W,X,Z,c,k,p,r,s,t,w,exit status (x), outputsum, errorsum"

# Get the current git revision we use this for our output
cd $LIBTRACE
GITREV=$(git rev-parse HEAD)
cd -
echo "Git revision is $GITREV"

#Name our results
TIME=$(date +%Y%m%d-%T)
RESULTSDIR=$TIME-$GITREV
cd $TRACES
mkdir $RESULTSDIR
cd $RESULTSDIR

# Now lets run the timings single threaded
for tracefile in $TRACES/*.gz
do
	OUTFILENAME=$(basename $tracefile)
	OUTFILENAME=tracestats-$OUTFILENAME.csv
	echo $CSVHEADINS > $OUTFILENAME
	# Load this file into memory so disk I/O is less important
	cat $tracefile > /dev/null
	echo "Running tracestats (singlethreaded) on $tracefile"
	for i in {1..5}
	do
		printf "\tRun $i : "
		/usr/bin/time -o times -f "$i,$TIMEFORMAT" $TRACESTATS $TRACESTATSARGS erf:$tracefile 1>$OUTFILENAME.stdout$i 2>$OUTFILENAME.stderr$i
		STDERRSUM=$(md5sum $OUTFILENAME.stderr$i | cut -f1 -d ' ')
		STDOUTSUM=$(md5sum $OUTFILENAME.stdout$i | cut -f1 -d ' ')
		echo "stdout=$STDOUTSUM stderr=$STDERRSUM"
		TIMESOUTPUT=$(cat times | tr -d "\n")
		echo "$TIMESOUTPUT,$STDOUTSUM,$STDERRSUM" >> $OUTFILENAME
		# clean up times
		rm times
	done
	printresults $OUTFILENAME
done

# Now lets do the parallel version
for tracefile in $TRACES/*.gz
do
	OUTFILENAME=$(basename $tracefile)
	OUTFILENAME=tracestats_parallel-$OUTFILENAME.csv
	echo $CSVHEADINS > $OUTFILENAME
	# Load this file into memory so disk I/O is less important
	cat $tracefile > /dev/null
	echo "Running tracestats_parallel on $tracefile"
	for i in {1..5}
	do
		printf "Run $i : "
		/usr/bin/time -o times -f "$i,$TIMEFORMAT" $TRACESTATSP $TRACESTATSARGS erf:$tracefile 1>$OUTFILENAME.stdout$i 2>$OUTFILENAME.stderr$i
		STDERRSUM=$(md5sum $OUTFILENAME.stderr$i | cut -f1 -d ' ')
		STDOUTSUM=$(md5sum $OUTFILENAME.stdout$i | cut -f1 -d ' ')
		echo "Sums stdout=$STDOUTSUM stderr=$STDERRSUM"
		TIMESOUTPUT=$(cat times | tr -d "\n")
		echo "$TIMESOUTPUT,$STDOUTSUM,$STDERRSUM" >> $OUTFILENAME
		# clean up times
		rm times
	done
	printresults $OUTFILENAME
done

# Now lets do traceanon
for tracefile in $TRACES/*.gz
do
	OUTFILENAME=$(basename $tracefile)
	OUTFILENAME=traceanon-$OUTFILENAME.csv
	echo $CSVHEADINS > $OUTFILENAME
	# Load this file into memory so disk I/O is less important
	cat $tracefile > /dev/null
	echo "Running traceanon on $tracefile"
	for i in {1..5}
	do
		printf "Run $i : "
		/usr/bin/time -o times -f "$i,$TIMEFORMAT" $TRACEANON $TRACEANONARGS erf:$tracefile erf:$LARGEOUTPUT/output.erf 1>$OUTFILENAME.stdout$i 2>$OUTFILENAME.stderr$i
		STDERRSUM=$(md5sum $OUTFILENAME.stderr$i | cut -f1 -d ' ')
		STDOUTSUM=$(md5sum $LARGEOUTPUT/output.erf | cut -f1 -d ' ')
		# this will be big but we just check the sums
		rm $LARGEOUTPUT/output.erf
		echo "Sums stdout=$STDOUTSUM stderr=$STDERRSUM"
		TIMESOUTPUT=$(cat times | tr -d "\n")
		echo "$TIMESOUTPUT,$STDOUTSUM,$STDERRSUM" >> $OUTFILENAME
		# clean up times
		rm times
	done
	printresults $OUTFILENAME
done

# Now lets do traceanon_parallel
for tracefile in $TRACES/*.gz
do
	OUTFILENAME=$(basename $tracefile)
	OUTFILENAME=traceanon_parallel-$OUTFILENAME.csv
	echo $CSVHEADINS > $OUTFILENAME
	# Load this file into memory so disk I/O is less important
	cat $tracefile > /dev/null
	echo "Running traceanon_parallel on $tracefile"
	for i in {1..5}
	do
		printf "Run $i : "
		/usr/bin/time -o times -f "$i,$TIMEFORMAT" $TRACEANONP $TRACEANONARGS erf:$tracefile erf:$LARGEOUTPUT/output.erf 1>$OUTFILENAME.stdout$i 2>$OUTFILENAME.stderr$i
		STDERRSUM=$(md5sum $OUTFILENAME.stderr$i | cut -f1 -d ' ')
		STDOUTSUM=$(md5sum $LARGEOUTPUT/output.erf | cut -f1 -d ' ')
		# this will be big but we just check the sums
		rm $LARGEOUTPUT/output.erf
		echo "Sums stdout=$STDOUTSUM stderr=$STDERRSUM"
		TIMESOUTPUT=$(cat times | tr -d "\n")
		echo "$TIMESOUTPUT,$STDOUTSUM,$STDERRSUM" >> $OUTFILENAME
		# clean up times
		rm times
	done
	printresults $OUTFILENAME
done
