%{
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <assert.h>
    #include "grammar.h"
    #include "libpacketdump.h"
    #include "bitbuffer.h"

    #define YYERROR_VERBOSE 1

    
    int yylex(void);

    char *file;
    element_t *el_list = NULL;

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

