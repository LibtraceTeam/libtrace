#include "output.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <lt_inttypes.h>

static void output_html_init(struct output_data_t *out)
{
	int i;
	printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n");
	printf("<html>\n");
	printf("<head>\n");
	printf(" <title>%s</title>\n",out->title);
	printf(" <style type=\"text/css\">\n");
	printf("  table         { border-collapse: collapse; width: 100%%}\n");
	printf("  td            { border: thin black solid; }\n");
	printf("  .numeric      { text-align: right; }\n");
	printf("  .even         { background: #e0e0e0; }\n");
	printf("  .odd          { background: #ffffff; }\n");
	printf("  .rowheading   { text-align: right; }\n");
	printf(" </style>\n");
	printf("</head>\n");
	printf("<body>\n");
	printf("<h1>%s</h1>\n",out->title);
	printf("<table>\n");
	printf(" <tr>\n");
	for(i=0;i<out->columns;++i) {
		printf("  <th>%s</th>",out->labels[i]);
	}
	printf(" </tr>\n");
	out->private_format_data=malloc(sizeof(int));
	*(int*)out->private_format_data=0;
}

static void output_html_flush(struct output_data_t *out)
{
	int i;
	printf(" <tr class=\"%s\">\n",((*(int*)out->private_format_data)++)&1?"odd":"even");
	for(i=0;i<out->columns;++i) {
		switch (out->data[i].type) {
			case TYPE_int: 
				printf("  <td class=\"numeric\">%" PRIu64 "</td>\n",out->data[i].d.d_int);
				break;
			case TYPE_str:
				printf("  <td>%s</td>\n",out->data[i].d.d_str);
				free(out->data[i].d.d_str);
				break;
			case TYPE_float:
				printf("  <td class=\"numeric\">%f</td>\n",out->data[i].d.d_float);
				break;
			case TYPE_time:
				printf("  <td class=\"numeric\">%.03f</td>\n",out->data[i].d.d_time);
				break;
		}
	}
	printf(" </tr>\n");
}

static void output_html_destroy(struct output_data_t *out)
{
	(void)out;
	printf("</table>\n");
	printf("</body>\n");
	printf("</html>\n");
}

struct output_type_t output_html = {
.name= "html",
.init= output_html_init,
.flush= output_html_flush,
.destroy= output_html_destroy,
};
