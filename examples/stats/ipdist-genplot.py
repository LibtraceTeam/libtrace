#!/usr/bin/python

import sys
import subprocess
import os
import re

# Ensure a data directory was supplied
if len(sys.argv) != 2:
	print("Usage: python3 data-directory")
	sys.exit()

dir = sys.argv[1]
dataFiles = []

# Stats
total_skew_src = [0, 0, 0, 0]
total_skew_dst = [0, 0, 0, 0]

# Get all data/stats files contained within the directory
for file in os.listdir(dir):
	if file.endswith(".data"):
		dataFiles.append(file)

# sort the datafiles list so they are read in the correct order
dataFiles.sort()

# Every datafile should have a corresponding stats file
# Iterate over every dataFile
for i in range(len(dataFiles)):
	dataFile = dataFiles[i]
	filename,extension = dataFiles[i].split(".")
	statsFile = filename + ".stats"
	tick = filename.split("-")
	tick = tick[1]

	# Open the current stats file
	lines = []
	with open(dir + "/" + statsFile, "r") as tmp:
		lines = tmp.readlines()
	# increment the total skew counters
	for x in range(4):
		total_skew_src[x] += float(lines[(4*x)+1].split()[6])
		total_skew_dst[x] += float(lines[(4*x)+2].split()[6])

	# Create/append to timeseries stats file
	# the file needs to be created on the first pass
	if i == 0:
		tmp = open(dir + "/ipdist-timeseries-skewness.stats", "w")
		tmp.write("timestamp\tsrc1\t\tdst1\t\tsrc2\t\tdst2\t\tsrc3\t\tdst3\t\tsrc4\t\tdst4\n")
	else:
		tmp = open(dir + "/ipdist-timeseries-skewness.stats", "a")
	tmp.write(tick)
	for x in range(4):
		tmp.write("\t" + str(total_skew_src[x]/(i+1)) + "\t" + str(total_skew_dst[x]/(i+1)))
	tmp.write("\n")
	tmp.close()



	# open data file to read from and count all occurances
	with open(dir + "/" + dataFile, "r") as tmp:
		lines = tmp.readlines()
	tmp.close()
	# Count up all octet count in current data file
	count_src = [0] * 4
	count_dst = [0] * 4
	# initialize the array
	for x in range(4):
		count_src[x] = [0] * 256
		count_dst[x] = [0] * 256
	# count all occurances
	for x in range(256):
		for k in range(4):
			count_src[k][int(lines[x+2].split()[(k*4)+2])] = int(lines[x+2].split()[(k*4)+3])
			count_dst[k][int(lines[x+2].split()[(k*4)+4])] = int(lines[x+2].split()[(k*4)+5])
	# output the results to the timeseries file
	tmp_src = []
	tmp_dst = []
	if i == 0:
		for x in range(4):
			tmp_src.append(open(dir + "/ipdist-src-octet" + str(x+1) + ".timeseries", "w"))
			tmp_dst.append(open(dir + "/ipdist-dst-octet" + str(x+1) + ".timeseries", "w"))
			tmp_src[x].write("timestamp")
			tmp_dst[x].write("timestamp")
			for k in range(256):
				tmp_src[x].write("\t" + str(k))
				tmp_dst[x].write("\t" + str(k))
	else:
		for x in range(4):
			tmp_src.append(open(dir + "/ipdist-src-octet" + str(x+1) + ".timeseries", "a"))
                        tmp_dst.append(open(dir + "/ipdist-dst-octet" + str(x+1) + ".timeseries", "a"))
	# print data into file
	for x in range(4):
		tmp_src[x].write("\n" + tick)
		tmp_dst[x].write("\n" + tick)
		for k in range(256):
			tmp_src[x].write("\t" + str(count_src[x][k]))
			tmp_dst[x].write("\t" + str(count_dst[x][k]))
	# close all files
	for x in range(4):
		tmp_src[x].close()
		tmp_dst[x].close()


	# create interval plots
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

