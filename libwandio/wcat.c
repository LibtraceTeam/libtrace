#include "wandio.h"
#include <ctype.h>
#include <err.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int compress_level = 0;
    int compress_type = WANDIO_COMPRESS_NONE;
    char *output = "-";
    char c;
    while ((c = getopt (argc, argv, "Z:z:o:")) != -1) {
        switch (c)
        {
            case 'Z':
                compress_type = wandio_lookup_compression_type(optarg)
                        ->compress_type;
                break;
            case 'z':
                compress_level = atoi(optarg);
                break;
            case 'o':
                output = optarg;
                 break;
           case '?':
             if (optopt == 'Z' || optopt == 'z' || optopt == 'o')
               fprintf (stderr, "Option -%c requires an argument.\n", optopt);
             else if (isprint (optopt))
               fprintf (stderr, "Unknown option `-%c'.\n", optopt);
             else
               fprintf (stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
             return 1;
           default:
             abort ();
           }
    }

    iow_t *iow = wandio_wcreate(output, compress_type, compress_level, 0);
                /* stdout */
    int i;
    for(i=optind; i<argc; ++i) {
        char buffer[1024*1024];
        io_t *ior = wandio_create(argv[i]);
        if (!ior) {
            fprintf(stderr, "Failed to open %s\n", argv[i]);
            continue;
        }

        off_t len;
        do {
            len = wandio_read(ior, buffer, sizeof(buffer));
            if (len > 0)
                wandio_wwrite(iow, buffer, len);
        } while(len > 0);

        wandio_destroy(ior);
    }
    wandio_wdestroy(iow);
    return 0;
}
