#include "bitbuffer.h"
#include <inttypes.h>
#include "parser.h"
#include <stdio.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "libpacketdump.h"

uint16_t bits;
/* "the largest possible type the compiler supports" */
bitbuffer_t buffer;

static bitbuffer_t getbit(void **packet, int *packlen, uint64_t numbits)
{
    bitbuffer_t ret;
    bitbuffer_t mask;
    
    char *pktptr = NULL;

    /* While the buffer is not filled up and there is still
     * data in the packet to read, read a byte...
     * 
     * The buffer gets filled from right to left
     */
    while(bits < numbits && *packlen > 0)
    {
	uint8_t byte;
	/* read in one byte from the packet */
	byte=(*((bitbuffer_t*)*packet))&0xff;
	buffer |= (bitbuffer_t)byte << (sizeof(bitbuffer_t)*8-(bits+sizeof(byte)*8));
	/* update the position within the packet */
	pktptr = (char *)*packet;
	pktptr += 1;
	*packet = pktptr;

	//*packet = ((char*)*packet) + 1;

	bits += sizeof(byte)*8;
	*packlen -= 1;
    }

    /* our return value is the first <numbits> of the buffer */
    mask = ~((1ULL<<((sizeof(bitbuffer_t)*8-numbits)))-1);
    ret = buffer & mask;
    ret >>=(sizeof(bitbuffer_t)*8-numbits);
    
    /* remove the bits that are being returned from out buffer */
    buffer <<= numbits;

    /* and update our position inside this buffer */
    bits -= numbits;

    return ret;
}

int yyparse(void);

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


static bitbuffer_t fix_byteorder(bitbuffer_t value,
		enum byte_order_t order, uint64_t size)
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



void decode_protocol_file(uint16_t link_type UNUSED,const char *packet,int len,element_t *el)
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
			printf(" %s %" PRIi64 "\n", 
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
			printf(" %s 0x%" PRIx64 "\n", 
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








int yyerror(const char *s)
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
#ifdef TEST
#include <stdio.h>
int main(void)
{
	unsigned char mybuffer[] = { 0x01, 0x82, 0x03, 0x04, 0x05, 0x06 };
	void *buf = mybuffer;
	int len=sizeof(buffer);
	printf("8bits=%"PRIx64"\n",getbit(&buf,&len,8));
	printf("2bits=%"PRIx64"\n",getbit(&buf,&len,2));
	return 0;
}
#endif
