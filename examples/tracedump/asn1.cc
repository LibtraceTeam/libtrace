#include <list>
#include <vector>
#include <stdint.h>
#include <assert.h>
#include <ctype.h>
#include <string>
#ifdef TEST
#include <stdio.h>
#endif
#include "asn1.h"


const char *const ASN_type_class_t_names[] = {
		"Universal",
		"Application",
		"Context Specific",
		"Private",
};

ASN_type::ASN_type(uint8_t _type) : type(_type){
	/* Not implemented multibyte tags yet */
	assert(getTag() != 0x1F);
}

ASN_type_class_t ASN_type::getClass(void) const {
	return (ASN_type_class_t) (type >> 6);
}

bool ASN_type::isPrimative(void) const {
	return !((type >> 5) & 0x01);
}

int ASN_type::getTag(void) const {
	return (type & 0x1F);
}

ASN_data::ASN_data(ASN_type _type,uint64_t _len) : type(_type),
						len(_len) 
{
};

void ASN_data::parse(void) 
{
};

void ASN_data::toString(void) {
			printf(" ASN: %s %s 0x%x\n",
					ASN_type_class_t_names[(int)type.getClass()],
					type.isPrimative() 
						? "Primative" 
						: "Constructed",
					type.getTag()
			      );
			buffer_t::const_iterator it=buffer.begin();
			while(it!=buffer.end()) {
				printf(" ASN:");

				buffer_t::const_iterator hexit=it;
				for(uint64_t i=0;i<8;i++) {
					if (hexit!=buffer.end()) {
						printf(" %02x",*hexit);
						hexit++;
					}
					else
						printf("   ");
				}
				printf("\t");
				for(uint64_t i=0;i<8;i++) {
					if (it!=buffer.end()) {
						printf("%c",
							isprint(*it)
							? *it
							: '.');
						it++;
					}
				}
				printf("\n");
			}
		}; // toString 
ASN_data::~ASN_data() {};


bool ASN::eof(void) const { 
	return buffer.size()<=0; 
}

// Type 0 - End of contents
// Type 1 - Bool
class ASN_bool : public ASN_data {
	public:
		ASN_bool(ASN_type t,uint64_t l) : ASN_data(t,l) {};
		bool getValue(void) const {
			return *buffer.begin()!=0;
		}
		void toString(void) const {
			printf(" ASN: Bool:\t%s\n",getValue()
						?"True":
						"False");
		}
};

// Type 2 - Integer
class ASN_int : public ASN_data {
	public:
		ASN_int(ASN_type t,uint64_t l) : ASN_data(t,l) {};
		uint64_t getValue(void) {
			uint64_t val=0;
			for(buffer_t::const_iterator i=buffer.begin();
					i!=buffer.end();
					i++) {
				val=(val<<8)+*i;
			}
			return val;
		}
		void toString(void) {
			printf(" ASN: Int:\t0x");
			// Yeah, this is a dirty trick
			for(buffer_t::const_iterator i=buffer.begin();
					i!=buffer.end();
					i++) {
				printf("%02x",*i);
			}
			printf("\n");
		}
};

// Types - Simple Strings
class ASN_string : public ASN_data {
	public:
		ASN_string(ASN_type t,uint64_t l) : ASN_data(t,l) {};
		std::string getValue(void) {
			std::string s;
			for(buffer_t::const_iterator i=buffer.begin();
					i!=buffer.end();
					i++) {
				s=s+(char)*i;
			}
			return s;
		}
		void toString(void) {
			printf(" ASN: String:\t%s\n",getValue().c_str());
		}
};
// Type 5 - Null
class ASN_null : public ASN_data {
	public:
		ASN_null(ASN_type t,uint64_t l) : ASN_data(t,l) {};
		void toString(void) { printf(" ASN: NULL\n"); }
};

// Abstract Container for sets and sequences
class ASN_container : public ASN_data {
	private:
		std::vector<ASN_data *> subencodings;
	public:
		typedef std::vector<ASN_data *>::const_iterator const_iterator;
		ASN_container(ASN_type t,uint64_t l) : ASN_data(t,l) {};
		void parse() {
			ASN n;
			n.feed(buffer,len);
			while (!n.eof()) {
				subencodings.push_back(n.getEncoding());
			}
		};
		const_iterator begin(void) { return (const_iterator)subencodings.begin(); }
		const_iterator end(void) { return (const_iterator)subencodings.end(); }
};

// Type 16 - Sequence 
class ASN_sequence : public ASN_container {
	public:
		ASN_sequence(ASN_type t,uint64_t l) : ASN_container(t,l) {};
		void toString(void) {
			printf(" ASN: Sequence begin\n");
			for(const_iterator i=begin();
					i!=end();
					i++)
				(*i)->toString();
			printf(" ASN: Sequence end\n");
		}
};
// Type 17 - Set
class ASN_set : public ASN_container {
	public:
		ASN_set(ASN_type t,uint64_t l) : ASN_container(t,l) {};
		void toString(void) {
			printf(" ASN: Set begin\n");
			for(const_iterator i=begin();
					i!=end();
					i++)
				(*i)->toString();
			printf(" ASN: Set end\n");
		}
};

// Type 6 - Object Identifier
class ASN_oid : public ASN_data {
	private:
		std::vector<uint64_t> oid;
		uint64_t decodeInt(void) {
			uint64_t x=0;
			while(*buffer.begin()&0x80) {
				x=(x<<7)|(*buffer.begin()&~0x80);
				buffer.pop_front();
			}
			x=(x<<7)|(*buffer.begin());
			buffer.pop_front();
			return x;
		}
	public:
		ASN_oid(ASN_type t,uint64_t l) : ASN_data(t,l) {};
		void parse(void) {
			uint64_t first = decodeInt();
			oid.push_back(first/40);
			oid.push_back(first%40);
			while(buffer.size()!=0)
				oid.push_back(decodeInt());
		};
		void toString(void) {
			printf(" ASN: OID");
			for(std::vector<uint64_t>::const_iterator i=oid.begin();
					i!=oid.end();
					i++) {
				printf(" %lli",*i);
			}
			printf("\n");
		};
};


void ASN::feed(char *buff,int size)
{
	while(size-->0) 
		buffer.push_back(*(buff++));
}


ASN_type ASN::getType(void)
{
	ASN_type t(*buffer.begin());
	buffer.pop_front();
	return t;
}

uint64_t ASN::getLength(void)
{
	// TODO Only supports definite encodings
	uint64_t len=0;
	uint8_t x = *buffer.begin();
	buffer.pop_front();
	assert(x != 0x80); // Indefinate encoding
	// Short form
	if ((x&0x80)==0) {
		return x;
	}
	x&=~0x80;
	// Long form
	while(x-->0) {
		len=(len<<8)|*buffer.begin();
		buffer.pop_front();
	}
	return len;
}

ASN_data *ASN::getEncoding(void) 
{
	ASN_type t=getType();
	uint64_t l=getLength();
	ASN_data *ret;
	switch(t.getTag()) {
		case 1:
			ret=new ASN_bool(t,l);
			break;
		case 2:
			ret=new ASN_int(t,l);
			break;
		case 5:
			ret=new ASN_null(t,l);
			break;
		case 6:
			ret=new ASN_oid(t,l);
			break;
		case 16:
			ret=new ASN_sequence(t,l);
			break;
		case 17:
			ret=new ASN_set(t,l);
			break;
		case 18:
		case 19:
		case 20:
		case 21:
		case 22:
		case 25:
		case 26:
		case 27:
			ret=new ASN_string(t,l);
			break;
		default:
			ret=new ASN_data(t,l);
			break;
	}
	ret->feed(buffer,l);
	ret->parse();
	return ret;
}

void ASN_data::feed(std::list<uint8_t> &buff,uint64_t len)
{
	while(len-->0) {
		buffer.push_back(*buff.begin());
		buff.pop_front();
	}
}

void ASN::feed(std::list<uint8_t> &buff,uint64_t len)
{
	while(len-->0) {
		buffer.push_back(*buff.begin());
		buff.pop_front();
	}
}
#ifdef TEST
int main(int argc, char **argv)
{
	FILE *f=fopen(argv[1],"r");
	ASN *asn = new ASN();;
	char buffer[1024];
	int size;

	size=fread(buffer,1,sizeof(buffer),f);
	printf("Read %i bytes\n",size);
	
	asn->feed(buffer,size);

	ASN_data *data= asn->getEncoding();
	
	data->toString();
	data->toString();

	return 0;
}
#endif
