DIGIT	    [0-9]
LETTER	    [a-zA-Z_: ]
HEXDIGIT    [0-9A-Fa-f]

%option noyywrap 
%option nounput 
%option noinput

%{
    #include <stdio.h>
    #include "grammar.h"
    #include "parser.h"

    int yylex(void);
    int yyerror(char *s);

    int lines = 1;
%}

%%

"#".*"\n"			{ /* ignore comments */ }		

"be"				{ return TOK_BIGENDIAN; }
"le"				{ return TOK_LITTLEENDIAN; }
"next"				{ return TOK_NEXT; }

"hex"				{ return TOK_OUTPUT_HEX;}
"integer"			{ return TOK_OUTPUT_INT;}
"ipv4"				{ return TOK_OUTPUT_IPV4;}
"mac"				{ return TOK_OUTPUT_MAC;}
"hidden"			{ return TOK_OUTPUT_NONE;}

"flag"				{ return TOK_OUTPUT_FLAG; }

{DIGIT}+	    		{ yylval.intval = atoi(yytext); 
				    return TOK_CONSTANT; }
\"[^\"]*\"			{ int i; 
				    for(i=0;yytext[i] != '\0'; i++)
					if(yytext[i] == '"')
					    yytext[i] = '\0';
				    yylval.textval = &yytext[1];
				    return TOK_IDENTIFIER;
				}

"\n"				{ lines++; }
.				{ /* ignore everything else */ }

%%

