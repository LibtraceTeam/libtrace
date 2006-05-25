%{
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <assert.h>
    #include "parser.h"
    #include "libpacketdump.h"

    #define YYERROR_VERBOSE 1

    
    int yylex(void);
    int yyerror(char *s);
    element_t *append(element_t *list, element_t *item);
    void print_list(element_t *list);

    extern FILE* yyin;
    extern char* yytext;
    extern int lines;
    char *file;
    element_t *el_list = NULL;

    /* i didnt want these to be global, but i think they have to be? :/ */
    static bitbuffer_t buffer = 0;
    static int bits = 0;
%}


%union {
    int intval;
    char *textval;
    element_t *ptr;
}

%token TOK_BIGENDIAN TOK_LITTLEENDIAN TOK_NEXT TOK_OUTPUT_INT TOK_OUTPUT_HEX TOK_OUTPUT_IPV4 TOK_OUTPUT_FLAG TOK_CONSTANT TOK_IDENTIFIER TOK_OUTPUT_MAC TOK_OUTPUT_NONE

%type <intval> TOK_BIGENDIAN TOK_LITTLEENDIAN TOK_NEXT TOK_OUTPUT_INT TOK_OUTPUT_HEX TOK_OUTPUT_IPV4 TOK_OUTPUT_FLAG TOK_OUTPUT_NONE TOK_CONSTANT output byteorder size '"'
%type <textval> TOK_IDENTIFIER identifier
%type <ptr> element nextfile elements

%%

config:	    elements nextfile { /*print_list(el_list);*/ }
	   ;
	
elements:   element 
	  | elements element { }
	  ;

element:    byteorder size output identifier { 
		node_t *n;
		element_t *el;
		/* create a new field node... */
	        field_t *new_field = (field_t *)malloc(sizeof(field_t)); 
		new_field->order = $1;
		new_field->size = $2;
		new_field->display = $3;
		new_field->identifier = $4;

		/* to go inside a new node... */
		n = (node_t *)malloc(sizeof(node_t));
		n->field = new_field;

		/* to go inside a new element */
		el = (element_t *)malloc(sizeof(element_t));		
		el->type = FIELD;
		el->next = NULL;
		el->data = n;
		
		/* and stick the new element on the end of our list */
		el_list = append(el_list, el);
	    }
	  ;

byteorder: TOK_BIGENDIAN { $$ = BIGENDIAN; }
	    | TOK_LITTLEENDIAN { $$ = LITTLEENDIAN; }
	  ;

size:	TOK_CONSTANT { $$ = yylval.intval; }
	;

output:   TOK_OUTPUT_HEX    { $$ = DISPLAY_HEX; }
	| TOK_OUTPUT_INT    { $$ = DISPLAY_INT; }
	| TOK_OUTPUT_IPV4   { $$ = DISPLAY_IPV4; }
	| TOK_OUTPUT_FLAG   { $$ = DISPLAY_FLAG; }
	| TOK_OUTPUT_MAC    { $$ = DISPLAY_MAC; }
	| TOK_OUTPUT_NONE   { $$ = DISPLAY_NONE; }
	;


identifier: TOK_IDENTIFIER { $$ = strdup($1); }
	    ;


nextfile:   TOK_NEXT identifier identifier { 

		element_t *tmp;
		node_t *n;
		element_t *el;
	        next_t *nextheader = (next_t *)malloc(sizeof(next_t)); 
		nextheader->prefix = $2;
		nextheader->fieldname = $3;
		nextheader->target = NULL;
		
		for(tmp = el_list ;; tmp=tmp->next)
		{
		    /* 
		     * if we hit the end of the list or a nextheader then
		     * the field name we are looking for doesn't exist
		     * - this is an error but we can carry on and just
		     * not bother parsing anything after this header
		     */
		    if(tmp == NULL || tmp->type == NEXTHEADER)
		    {
			fprintf(stderr, "XXX No field match found for "
					"nextfield '%s'...ignoring\n", $3);
			$$ = NULL;
			break;
		    }
		    
		    /* 
		     * if the field name matches the one we are looking at,
		     * store a pointer to it so we can steal its value later
		     */
		    if(strcmp($3, tmp->data->field->identifier) == 0)
		    {
			nextheader->target = tmp->data->field;
			break;
		    }
		}
		
		n = (node_t *)malloc(sizeof(node_t));
		n->nextheader = nextheader;

		el = (element_t *)malloc(sizeof(element_t));		
		el->type = NEXTHEADER;
		el->next = NULL;
		el->data = n;
		
		el_list = append(el_list, el);
	    }
	|   { /*printf("no next file...\n");*/ $$ = NULL; }
	;


%%

#include "bitbuffer.h"

element_t* parse_protocol_file(char *filename)
{
    /* hold onto this so we can put it in any error messages */
    file = filename;

    /* if the protocol file doesn't exist, we return null and
     * it will fall back to using the generic_decode function
     */
    yyin = fopen(filename, "r");
    if(!yyin)
	return NULL;

    el_list = NULL;
    lines = 1;

    yyparse();
    fclose(yyin);
    return el_list;
}





bitbuffer_t fix_byteorder(bitbuffer_t value, enum byte_order_t order, uint64_t size)
{
    bitbuffer_t one = 1;
    bitbuffer_t lhs;
    bitbuffer_t rhs;;

    /*
     * XXX trial and error seems to show these numbers to work.
     * I've tried fields of length 1,2,3,4,8,13,16,32 and they seem to work.
     * Others are untested...
     */
    switch(order)
    {
	case BIGENDIAN: 
	    if(size < 16)
		return value;
	    if(size < 32)
		return ntohs(value);
	    if(size <= 32)
		return ntohl(value);
	    
	    lhs = ntohl(value& ((one<<32)-1));
	    rhs = ntohl(value >> 32);
	    return ((lhs<<32) | rhs);

	case LITTLEENDIAN: 
	    return value;

    };

    /* should never get here */
    assert(0);
    return 0;
}



void decode_protocol_file(uint16_t link_type,char *packet,int len,element_t *el)
{
    bitbuffer_t result;

    while(el != NULL)
    {
	switch(el->type)
	{
	    case FIELD:
	    	if (len*8+bits<el->data->field->size) {
			printf(" [Truncated]\n");
			return;
		}
		result = getbit((void*)&packet, &len, el->data->field->size); 

		switch(el->data->field->display)
		{
		    /* integers get byteswapped if needed and displayed */
		    case DISPLAY_INT: 
		    {
			result = fix_byteorder(result, 
				el->data->field->order, 
				el->data->field->size);
				
			el->data->field->value = result;
			printf(" %s %lld\n", 
				el->data->field->identifier,
				result);
		    }
		    break;

		    /* 
		     * hex numbers get byteswapped if needed and displayed 
		     * without being padded with zeroes
		     */
		    case DISPLAY_HEX: 
		    { 
			result = fix_byteorder(result, 
				el->data->field->order, 
				el->data->field->size);
			
			el->data->field->value = result;
			printf(" %s 0x%llx\n", 
				el->data->field->identifier,
				result);
		    }
		    break;
		    
		    /* 
		     * ipv4 addresses stay in network byte order and are
		     * given to inet_ntoa() to deal with
		     */
		    case DISPLAY_IPV4: 
		    {
			/* assumes all ipv4 addresses are 32bit fields */
			struct in_addr address;
			address.s_addr = (uint32_t)result;
			el->data->field->value = result;
		    
			printf(" %s %s\n", 
				el->data->field->identifier,
				inet_ntoa(address));
		    }
		    break;

		    /* 
		     * mac addresses stay in network byte order and are
		     * displayed byte by byte with zero padding
		     */
		    case DISPLAY_MAC: 
		    {
			/* assumes all mac addresses are 48bit fields */
			uint8_t *ptr = (uint8_t*)&result;
			el->data->field->value = result;
			printf(" %s %02x:%02x:%02x:%02x:%02x:%02x\n",
				el->data->field->identifier,
				ptr[0], ptr[1], ptr[2], 
				ptr[3], ptr[4], ptr[5]);
		    }
		    break;
		    
		    /*
		     * Flag values are only displayed if their value is true
		     * otherwise they are ignored
		     */
		    case DISPLAY_FLAG: 
		    {
			el->data->field->value = result;
			if(result)
			    printf(" %s\n", el->data->field->identifier);
		    }
		    break;

		    /*
		     * Hidden values are not displayed at all. This is useful
		     * for reserved fields or information that you don't care
		     * about but need to read in order to get to the rest of
		     * the header
		     */
		    case DISPLAY_NONE: 
		    {
			result = fix_byteorder(result, 
				el->data->field->order, 
				el->data->field->size);
			el->data->field->value = result;
		    }
		    break;
		};

		break;

	    case NEXTHEADER:
		/* 
		 * Before we move on to the next header, make sure our packet
		 * pointer is pointing to the first unused bytes. This may
		 * mean we have to backtrack to some that were put into the
		 * buffer but weren't used.
		 * - This wouldn't be a problem if all future output came
		 * from this buffer, but there is a good chance we will use
		 * some code from a shared library to output packet info
		 * instead, and this doesn't have access to the buffer.
		 */
		packet = packet - (bits / 8);
		len = len + (bits / 8);
		bits = 0;
		buffer = 0;

		decode_next(packet, len, el->data->nextheader->prefix, 
			ntohs(el->data->nextheader->target->value));
		break;
	};
	
	el = el->next;
    }
    buffer = 0;
    bits = 0;

}








int yyerror(char *s)
{
    element_t *tmp;
    
    fprintf(stderr, "XXX %s\n"
		    "XXX %s on line %d\n"
		    "XXX Falling back to generic_decode()\n", 
		    file, s, lines);
    /* 
     * Clear the list so we don't do partial matching...makes it a bit
     * more obvious that something is broken perhaps.
     * XXX Not sure if it is better to parse none of the packet, or part 
     * of the packet in the event of error? Feel free to remove this if
     * that is desired.
     */

    while(el_list != NULL)
    {
	tmp = el_list;
	el_list = el_list->next;

	switch(tmp->type)
	{
	    case FIELD: free(tmp->data->field); break;
	    case NEXTHEADER: free(tmp->data->nextheader); break;
	}
	free(tmp->data);	
	free(tmp);
	printf("deleting...\n");
    }

    return 0;
}

/*
 * Could be shortcut with a pointer to the tail...
 */
element_t* append(element_t *list, element_t *item)
{
    if(list == NULL)
	return item;

    list->next = append(list->next, item);
    return list;
}
/*
 * Testing...
 */
void print_list(element_t *list)
{
    if(list == NULL)
	return;
	
    switch(list->type)
    {
	case NEXTHEADER: printf("*Nextheader, prefix='%s', target='%s'\n", 
			    list->data->nextheader->prefix, 
			    list->data->nextheader->fieldname);
			    break;
	
	case FIELD: printf("*Field, order = '%d', size = '%d', "
			    "display='%d', name='%s'\n",
			    list->data->field->order, 
			    list->data->field->size, 
			    list->data->field->display,
			    list->data->field->identifier);
			    break;
    };
    /*printf("%s\n", list->data->identifier); */
    print_list(list->next);
}
