#include "output.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <string.h>

#define COLWIDTH 11

static void output_txt_init(struct output_data_t *out)
{
	int i;
	for(i=0;i<out->columns;++i) {
		if (strlen(out->labels[i])>8)
			printf("[%i]: %s\n",i,out->labels[i]);
	}
	printf("\n");
	for(i=0;i<out->columns;++i) {
		if (strlen(out->labels[i])>8)
			printf("[%*i] ",COLWIDTH-3,i);
		else
			printf("%*s ",COLWIDTH-1,out->labels[i]);
	}
	printf("\n");
}

static void output_txt_flush(struct output_data_t *out)
{
	int i;
	for(i=0;i<out->columns;++i) {
		switch (out->data[i].type) {
			case TYPE_int: 
				printf("%*" PRIu64 " ",COLWIDTH-1,out->data[i].d.d_int);
				break;
			case TYPE_str:
				printf("%*s ",COLWIDTH-1,out->data[i].d.d_str);
				free(out->data[i].d.d_str);
				break;
			case TYPE_float:
				printf("%*f ",COLWIDTH-1,out->data[i].d.d_float);
				break;
			case TYPE_time:
				printf("%*.0f ",COLWIDTH-1,out->data[i].d.d_time);
				break;
		}
	}
	printf("\n");
}

static void output_txt_destroy(struct output_data_t *out)
{
	(void)out;
	/* Do nothing */
}

struct output_type_t output_txt = {
.name= "txt",
.init= output_txt_init,
.flush= output_txt_flush,
.destroy= output_txt_destroy,
};
