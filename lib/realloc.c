#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif
#undef realloc

#include <sys/types.h>
#include <stdlib.h>

void *realloc ();


/* If N is zero, allocate a 1-byte block */
void *
rpl_realloc(void *ptr,size_t n)
{
	
	if (n == 0)
		n = 1;
	if (ptr == 0)
		return malloc(n);
	return realloc(ptr,n);
}
