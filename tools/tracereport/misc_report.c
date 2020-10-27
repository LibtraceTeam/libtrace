/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */


#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include "libtrace.h"
#include "tracereport.h"
#include "report.h"

static double starttime;
static double endtime;
static bool has_starttime = false;
static bool has_endtime = false;
static uint64_t packets = 0;

static uint64_t capture_bytes = 0;

void misc_per_packet(struct libtrace_packet_t *packet)
{
	double ts = trace_get_seconds(packet);
	if (ts != 0 && (!has_starttime || starttime > ts))
		starttime = ts;
	if (ts != 0 && (!has_endtime || endtime < ts))
		endtime = ts;
	has_starttime = has_endtime = true;
	++packets;
	capture_bytes += trace_get_capture_length(packet) + trace_get_framing_length(packet);
}

static char *ts_to_date(double ts)
{
	time_t sec = (time_t)ts;
	static char ret[1024];
	strncpy(ret,ctime(&sec),1024-1);
	ret[strlen(ret)-1]='\0'; /* Get rid of the annoying \n */
	return ret;
}

static char *duration(double ts)
{
	static char ret[1024];
	char tmp[128];
	ret[0]='\0';
	if (ts == 0) 
		return "0 seconds";
	if (ts>=24*60*60) {
		snprintf(ret,sizeof(ret),"%i days",(int)(ts/(24*60*60)));
		ts-=(int)(ts/(24*60*60))*24*60*60;
	}
	if (ts>=60*60) {
		snprintf(tmp,sizeof(tmp),"%s%i hours",
				ret[0]?", ":"",
				(int)ts/(60*60));
		strncat(ret,tmp, 1024 - strlen(ret) - 1);
		ts-=(int)(ts/(60*60))*60*60;
	}
	if (ts>=60) {
		snprintf(tmp,sizeof(tmp),"%s%i minutes",
				ret[0]?", ":"",
				(int)ts/60);
		strncat(ret,tmp, 1024 - strlen(ret) - 1);
		ts-=(int)(ts/60)*60;
	}
	if (ts>0) {
		snprintf(tmp,sizeof(tmp),"%s%.04f seconds",
				ret[0]?", ":"",
				ts);
		strncat(ret,tmp, 1024 - strlen(ret) - 1);
	}
	return ret;
}

void misc_report(void)
{
	FILE *out = fopen("misc.rpt", "w");
	if (!out) {
		perror("fopen");
		return;
	}
	fprintf(out, "Start time: %.04f (%s)\n",starttime,ts_to_date(starttime));
	fprintf(out, "End time: %.04f (%s)\n",endtime,ts_to_date(endtime));
	fprintf(out, "Duration: %.04f (%s)\n",endtime-starttime,
			duration(endtime-starttime));
	fprintf(out, "Total Packets: %" PRIu64 "\n",packets);
	fprintf(out, "Average packet rate: %.02f packets/sec\n",
			packets/(endtime-starttime));
	fprintf(out, "Uncompressed trace size: %" PRIu64 "\n", capture_bytes);
}
