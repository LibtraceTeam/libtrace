#ifndef _PARSER_H
#define _PARSER_H

#include <inttypes.h>

enum node_type_t {
    NEXTHEADER,
    FIELD
};

enum byte_order_t {
    BIGENDIAN,
    LITTLEENDIAN
}; 

enum display_t {
    DISPLAY_NONE,
    DISPLAY_HEX,
    DISPLAY_INT,
    DISPLAY_IPV4,
    DISPLAY_MAC,
    DISPLAY_FLAG
};

/* This is more complicated that I feel it needs to be... */

typedef struct next {
    char *prefix;		    /* search prefix for nextheader file */
    char *fieldname;		    /* name of the field whose value we use */
    struct field *target;	    /* link to the field whose value we use */
} next_t;
    
typedef struct field {
    enum byte_order_t order;	    /* byte order of field */
    uint16_t size;		    /* size of the field in bits */
    enum display_t display;	    /* how the data should be displayed */
    char *identifier;		    /* display prefix + field identifier */
    uint64_t value;		    /* calculated value for this field */
} field_t; 

typedef union node {
    field_t *field;
    next_t *nextheader;
} node_t;

typedef struct element {
    enum node_type_t type;
    struct element *next;
    node_t *data;
} element_t;
    
element_t *parse_protocol_file(char *filename);
void decode_protocol_file(uint16_t link_type,const char *packet,int len, element_t* el);

typedef uint64_t bitbuffer_t;
#endif
