// :!gcc -o bsearch_test -Ilib/asn1/ bsearch_test.c oid.c<CR>

//typedef struct ASN__PRIMITIVE_TYPE_s {
    //const uint8_t *buf;   /* Buffer with consecutive primitive encoding bytes */
    //size_t size;    /* Size of the buffer */
//} ASN__PRIMITIVE_TYPE_t;	/* Do not use this type directly! */

//typedef ASN__PRIMITIVE_TYPE_t OBJECT_IDENTIFIER_t;

#include "oid.h"

uint8_t data[] = {
	0, 2, 4, 6, 8, 
};

int cmp_uint8_t(const void* a_, const void* b_) {
	uint8_t a = *(uint8_t*)a_;
	uint8_t b = *(uint8_t*)b_;
	return a - b;
}

int main(int argc, char** argv) {
	printf("bsearch test\n");

	uint8_t key = 8;
	void* res = bsearch(&key, data, sizeof(data)/sizeof(data[0]), sizeof(data[0]), &cmp_uint8_t);
	printf("res: %p\n", res);
	if(res) {
		printf("value: %d\n", *(uint8_t*)res);
	}

	OBJECT_IDENTIFIER_t oid_key = {
		(uint8_t[]){0x04,0x00,0x7F,0x00,0x07}, 5
	};

	int nid = oid_oid2nid(&oid_key);
	printf("NID: %d\n", nid);

	/*
	res = bsearch(&obj_nids[3], obj_nids, sizeof(obj_nids)/sizeof(obj_nids[0]), sizeof(obj_nids[0]), &cmp_OBJECT_IDENTIFIER_t);
	printf("res: %p\n", res);
	if(res) {
		OID_NID_t* found = (OID_NID_t*)res;
		int idx = ((OID_NID_t*)res) - obj_nids;
		printf("Found, idx: %d, size: %ld, NID: %d\n", idx, found->oid.size, found->nid);
		for(size_t i=0; i<found->oid.size; ++i) {
			printf("%02X ", found->oid.buf[i]);
		}
		printf("\n");
		//printf("value: %d\n", *(uint8_t*)res);
	}
	*/

	return 0;
}
