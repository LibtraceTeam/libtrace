#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include "libtrace.h"
#include "tracereport.h"

static double starttime;
static double endtime;
static bool has_starttime = false;
static bool has_endtime = false;
static uint64_t packets = 0;

void misc_per_packet(struct libtrace_packet_t *packet)
{
	double ts = trace_get_seconds(packet);
	if (!has_starttime || starttime > ts)
		starttime = ts;
	if (!has_endtime || endtime < ts)
		endtime = ts;
	has_starttime = has_endtime = true;
	++packets;
}

static char *ts_to_date(double ts)
{
	time_t sec = (time_t)ts;
	static char ret[1024];
	strcpy(ret,ctime(&sec));
	ret[strlen(ret)-1]='\0'; /* Get rid of the annoying \n */
	return ret;
}

static char *duration(double ts)
{
	static char ret[1024];
	char tmp[1024];
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
		strcat(ret,tmp);
		ts-=(int)(ts/(60*60))*60*60;
	}
	if (ts>=60) {
		snprintf(tmp,sizeof(tmp),"%s%i minutes",
				ret[0]?", ":"",
				(int)ts/60);
		strcat(ret,tmp);
		ts-=(int)(ts/60)*60;
	}
	if (ts>0) {
		snprintf(tmp,sizeof(tmp),"%s%.04f seconds",
				ret[0]?", ":"",
				ts);
		strcat(ret,tmp);
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
}
