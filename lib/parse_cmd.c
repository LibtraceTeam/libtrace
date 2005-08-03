void
skip_white(char **buf)
{
	while(**buf==' ')
		(*buf)++;
}

/* Get the next word in a line
 *
 * Returns
 *  NULL : End of line
 *  other: Pointer to a word
 *
 * Side effects:
 *  updates *buf
 *  modified *buf
 * 
 * ' foo bar baz' => 'foo' 'bar baz'
 * ' "foo bar" baz' => 'foo bar' ' baz'
 */
char *
split_cmd(char **buf)
{
	char *ret = 0;

	skip_white(buf);

	if (**buf=='"') /* Quoted */
	{
		(*buf)++;
		ret=*buf;

		while(**buf && **buf!='"')
			(*buf)++;

		if (**buf)
		{
			**buf='\0';
			(*buf)++;
		}
	} else 
	{
		ret=*buf;

		while(**buf && **buf!=' ')
			(*buf)++;

		if (**buf)
		{
			**buf='\0';
			(*buf)++;
		}
	}
	return ret;
}

/* Split a command line up into parc,parv
 * using command line rules
 */
void parse_cmd(char *buf,int *parc, char *parv[], int MAXTOKENS)
{
	int i=0;
	*parc=0;

	while(*buf) 
	{
		parv[(*parc)++]=split_cmd(&buf);
		if (*parc>(MAXTOKENS-1))
		{
			parv[*parc]=buf;
			break;
		}
	}
	for(i=*parc;i<MAXTOKENS;i++)
		parv[i]="";
}
