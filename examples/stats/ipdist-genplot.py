#!/usr/bin/python

import sys
import subprocess
import os

# Ensure a data directory was supplied
if len(sys.argv) != 2:
	print("Usage: python data-directory")
	sys.exit()

dir = sys.argv[1]
dataFiles = []
statsFiles = []

# Get all data/stats files contained within the directory
for file in os.listdir(dir):
	if file.endswith(".data"):
		dataFiles.append(file)
	if file.endswith(".stats"):
		statsFiles.append(file)

# Every datafile should have a corresponding stats file
# Iterate over every dataFile
for i in range(len(dataFiles)):
	dataFile = dataFiles[i]
	filename,extension = dataFiles[i].split(".")
	statsFile = filename + ".stats"
	tick = filename.split("-")
	tick = tick[1]

	for x in range(4):
		plot = subprocess.Popen(['gnuplot -persistent','-p'],
					shell=True,
					stdin=subprocess.PIPE,)

		plot.stdin.write("set term pngcairo enhanced size 1280,960\n")
		plot.stdin.write("set output '" + dir + "/" + filename + "-octet" + str(x+1) + ".png'\n")
		plot.stdin.write("set multiplot layout 2,1\n")
		plot.stdin.write("set title 'IP Distribution - " + tick + "'\n")
		plot.stdin.write("set xrange[0:255]\n")
		plot.stdin.write("set y2range[-1:1]\n")
		plot.stdin.write("set y2tics\n")
		plot.stdin.write("set xlabel 'Prefix'\n")
		plot.stdin.write("set ylabel 'Hits'\n")
		plot.stdin.write("set y2label 'Skewness'\n")
		plot.stdin.write("set xtics 0,10,255\n")
		plot.stdin.write("stats '" + dir + "/" + statsFile + "' index " + str(x) + " every ::0::0 using 2 name 'SOURCEMEAN' nooutput\n")
		plot.stdin.write("stats '" + dir + "/" + statsFile + "' index " + str(x) + " every ::1::1 using 2 name 'DESTMEAN' nooutput\n")
		plot.stdin.write("stats '" + dir + "/" + statsFile + "' index " + str(x) + " every ::0::0 using 7 name 'SOURCESKEW' nooutput\n")
		plot.stdin.write("stats '" + dir + "/" + statsFile + "' index " + str(x) + " every ::1::1 using 7 name 'DESTSKEW' nooutput\n")
		plot.stdin.write("set arrow from SOURCEMEAN_min, graph 0 to SOURCEMEAN_min, graph 1 nohead lt 1\n")
		plot.stdin.write("set arrow from DESTMEAN_min, graph 0 to DESTMEAN_min, graph 1 nohead lt 2\n")
		plot.stdin.write("plot '" + dir + "/" + dataFile + "' using " + str((x*4)+3) + ":" + str((x*4)+4) + " index 0 title 'Source octet " + str(x+1) + "' smooth unique with boxes,")
		plot.stdin.write("'' using " + str((x*4)+5) + ":" + str((x*4)+6) + " index 0 title 'Destination octet " + str(x+1) + "' smooth unique with boxes,")
		plot.stdin.write("1/0 t 'Source mean' lt 1,")
		plot.stdin.write("1/0 t 'Destination mean' lt 2,")
		plot.stdin.write("SOURCESKEW_min title 'Source Skewness' axes x1y2,")
		plot.stdin.write("DESTSKEW_min title 'Destination Skewness' axes x1y2\n")
		plot.stdin.write("unset y2tics\n")
		plot.stdin.write("unset y2label\n")
		plot.stdin.write("unset arrow\n")
		plot.stdin.write("unset label 1\nunset label 2\nunset label 3\nunset label 4\nunset label 5\nunset label 6\n")
		plot.stdin.write("set title 'Zipf Distribution'\n")
		plot.stdin.write("set xlabel 'Rank'\n")
		plot.stdin.write("set ylabel 'Frequency'\n")
		plot.stdin.write("set logscale xy 10\n")
		plot.stdin.write("set xrange[1:255]\n")
		plot.stdin.write("set xtics 0,10,255\n")
		plot.stdin.write("plot '" + dir + "/" + dataFile + "' using 2:" + str((x*4)+4) + " index 0 title 'Source octet " + str(x+1) + "',")
		plot.stdin.write("'' using 2:" + str((x*4)+6) + " index 0 title 'Destination octet " + str(x+1) + "'\n")
		plot.stdin.flush()
		plot.communicate()


# Generate plots for the timeseries data captured over the entire trace
for i in range(4):
	for x in range(2):
		plot = subprocess.Popen(['gnuplot -persistent','-p'],
                                        shell=True,
                                        stdin=subprocess.PIPE,)
		plot.stdin.write("set term pngcairo size 1280,960\n")
		if x == 0:
			plot.stdin.write("set output '" + dir + "/ipdist-timeseries-src-octet" + str(i+1) + ".png'\n")
			plot.stdin.write("set title 'Timeseries src octet " + str(i+1) + "'\n")
		else:
			plot.stdin.write("set output '" + dir + "/ipdist-timeseries-dst-octet" + str(i+1) + ".png'\n")
			plot.stdin.write("set title 'Timeseries dst octet " + str(i+1) + "'\n")
		plot.stdin.write("set multiplot layout 2,1\n")
		plot.stdin.write("set xtics rotate\n")
		plot.stdin.write("set ytics\n")
		plot.stdin.write("set xlabel 'Timestamp'\n")
		plot.stdin.write("set key off\n")
		plot.stdin.write("set autoscale xy\n")
		if x == 0:
			plot.stdin.write("plot '" + dir + "/ipdist-src-octet" + str(i+1) + ".timeseries' using 2:xtic(1) with lines title columnheader(2) at end smooth cumulative, for[i=3:257] '' using i with lines title columnheader(i) at end smooth cumulative\n")
		else:
			plot.stdin.write("plot '" + dir + "/ipdist-dst-octet" + str(i+1) + ".timeseries' using 2:xtic(1) with lines title columnheader(2) at end smooth cumulative, for[i=3:257] '' using i with lines title columnheader(i) at end smooth cumulative\n")
		plot.stdin.write("set title 'Timeseries mean skewness'\n")
		plot.stdin.write("set yrange[-1:1]\n")
		plot.stdin.write("set xlabel 'Timestamp'\n")
		plot.stdin.write("set ylabel 'Skewness'\n")
		plot.stdin.write("plot '" + dir + "/ipdist-timeseries-skewness.stats' using " + str((i*2)+2+x) + ":xtic(1) with lines\n")
		plot.stdin.write("unset multiplot\n")
		plot.stdin.flush()
		plot.communicate()

