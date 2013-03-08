#include "grammar.h"
#include <stdio.h>
int yyerror(const char *s);
element_t *append(element_t *list, element_t *item);
void print_list(element_t *list);
extern char *file;
extern FILE* yyin;
extern char* yytext;
extern int lines;
extern element_t *el_list;

