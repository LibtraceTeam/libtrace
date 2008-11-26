#define HAVE_LIBFREETYPE
#define _GNU_SOURCE
#include "output.h"
#include <stdio.h>
#include <stdlib.h>
#include "gdc.h"
#include "gdchart.h"
#include "gdcpie.h"
#include <inttypes.h>
#include <lt_inttypes.h>
#include <err.h>

struct private_png_t {
	int rows;
	float *data;
};

static void output_png_init(struct output_data_t *out)
{
	out->private_format_data=malloc(sizeof(struct private_png_t));
	((struct private_png_t *)out->private_format_data)->rows=0;
	((struct private_png_t *)out->private_format_data)->data=0;
}

static void output_png_flush(struct output_data_t *out)
{
	int i;
	struct private_png_t *prv=out->private_format_data;
	prv->rows++;
	prv->data= realloc(prv->data,prv->rows*out->columns*sizeof(float));
	for(i=0;i<out->columns;++i) {
		switch (out->data[i].type) {
			case TYPE_int: 
				prv->data[out->columns*(prv->rows-1)+i]=out->data[i].d.d_int;
				break;
			case TYPE_str:
				free(out->data[i].d.d_str);
				break;
			case TYPE_float:
				prv->data[out->columns*(prv->rows-1)+i]=out->data[i].d.d_float;
				break;
			case TYPE_time:
				prv->data[out->columns*(prv->rows-1)+i]=out->data[i].d.d_time;
				break;
		}
	}
}

static void output_png_destroy(struct output_data_t *out)
{
	struct private_png_t *prv=out->private_format_data;
	int i,j;
	char *labels[prv->rows];
	float data1[(out->columns-1)/2][prv->rows];
	float data2[(out->columns-1)/2][prv->rows];
	for(i=0;i<prv->rows;++i) {
		if (asprintf(&labels[i],"%i",(int)prv->data[i*out->columns])==-1) {
			err(1,"Out of memory");
		}
		for(j=0;j<(out->columns-1)/2;++j) {
			data1[j][i]=prv->data[i*out->columns+j*2+1];
			data2[j][i]=prv->data[i*out->columns+j*2+2];
		}
	}

	GDC_image_type = GDC_PNG;
	GDC_title = out->title;
	GDC_out_graph( 640, 480,
			stdout,
			GDC_COMBO_LINE_LINE,
			prv->rows,
			labels,	
			(out->columns-1)/2,
			(float*)data1,
			(float*)data2);
	free(prv->data);
	free(prv);
}

struct output_type_t output_png = {
	.name= "png",
	.init= output_png_init,
	.flush= output_png_flush,
	.destroy= output_png_destroy,
};
