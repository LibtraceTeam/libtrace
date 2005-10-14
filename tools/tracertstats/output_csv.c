#include "output.h"
#include <stdio.h>
#include <stdlib.h>

static void output_csv_init(struct output_data_t *out)
{
	int i;
	for(i=0;i<out->columns;++i) {
		if (i!=0)
			printf(",");
		printf("%s",out->labels[i]);
	}
	printf("\n");
}

static void output_csv_flush(struct output_data_t *out)
{
	int i;
	for(i=0;i<out->columns;++i) {
		if (i!=0) printf(",");
		switch (out->data[i].type) {
			case TYPE_int: 
				printf("%" PRIu64,out->data[i].d_int);
				break;
			case TYPE_str:
				printf("%s",out->data[i].d_str);
				free(out->data[i].d_str);
				break;
			case TYPE_float:
				printf("%f",out->data[i].d_float);
				break;
			case TYPE_time:
				printf("%.03f",out->data[i].d_time);
				break;
		}
	}
	printf("\n");
}

static void output_csv_destroy(struct output_data_t *out)
{
	/* Do nothing */
}

struct output_type_t output_csv = {
name: "csv",
init: output_csv_init,
flush: output_csv_flush,
destroy: output_csv_destroy,
};
