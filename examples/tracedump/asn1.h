#ifndef ASN1_H
#define ASN1_H

#include <list>

enum ASN_type_class_t {
		Universal = 0,
		Application = 1,
		Context = 2, /* Context Specific */
		Private = 3,
};

class ASN_type {
	public:
		uint8_t type;
		ASN_type(uint8_t _type);
		ASN_type_class_t getClass(void) const;
		bool isPrimative(void) const;
		int getTag(void) const;
};

class ASN_data {
	public:
		ASN_type type;
		uint64_t len;
		typedef std::list<uint8_t> buffer_t;
		buffer_t buffer;

		ASN_data(ASN_type _type,uint64_t _len);

		void feed(std::list<uint8_t> &buffer,uint64_t len);
		virtual void parse(void);

		virtual void toString(void);
		virtual ~ASN_data();
};

class ASN {
		typedef std::list <uint8_t> buffer_t;
		buffer_t buffer;
	public:
		void feed(char *buff,int size);
		void feed(std::list<uint8_t> &buff,uint64_t len);
		ASN_type getType(void);
		uint64_t getLength(void);
		ASN_data *getEncoding(void); 
		bool eof(void) const;
};

#endif
