#include <stdio.h>
#include <stdint.h>
#include <memory.h>


#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)bsearch.c	8.1 (Berkeley) 6/4/93";
#endif /* LIBC_SCCS and not lint */
#include <sys/cdefs.h>

#include <stddef.h>
#include <stdlib.h>

/*
 * Perform a binary search.
 *
 * The code below is a bit sneaky.  After a comparison fails, we
 * divide the work in half by moving either left or right. If lim
 * is odd, moving left simply involves halving lim: e.g., when lim
 * is 5 we look at item 2, so we change lim to 2 so that we will
 * look at items 0 & 1.  If lim is even, the same applies.  If lim
 * is odd, moving right again involes halving lim, this time moving
 * the base up one item past p: e.g., when lim is 5 we change base
 * to item 3 and make lim 2 so that we will look at items 3 and 4.
 * If lim is even, however, we have to shrink it by one before
 * halving: e.g., when lim is 4, we still looked at item 2, so we
 * have to make lim 3, then halve, obtaining 1, so that we will only
 * look at item 3.
 */
void* bsearch(key, base0, nmemb, size, compar) const void* key;
const void* base0;
size_t nmemb;
size_t size;
int (*compar)(const void*, const void*);
{
    const char* base = base0;
    size_t lim;
    int cmp;
    const void* p;

    for(lim = nmemb; lim != 0; lim >>= 1) {
        p = base + (lim >> 1) * size;
        cmp = (*compar)(key, p);
        if(cmp == 0) return ((void*)p);
        if(cmp > 0) { /* key > p: move right */
            base = (char*)p + size;
            lim--;
        } /* else move left */
    }
    return (NULL);
}

#ifdef __BLOCKS__
void* bsearch_b(key, base0, nmemb, size, compar) const void* key;
const void* base0;
size_t nmemb;
size_t size;
int (^compar)(const void*, const void*);
{
    const char* base = base0;
    size_t lim;
    int cmp;
    const void* p;

    for(lim = nmemb; lim != 0; lim >>= 1) {
        p = base + (lim >> 1) * size;
        cmp = compar(key, p);
        if(cmp == 0) return ((void*)p);
        if(cmp > 0) { /* key > p: move right */
            base = (char*)p + size;
            lim--;
        } /* else move left */
    }
    return (NULL);
}
#endif /* __BLOCKS__ */

uint8_t data[] = {
	0, 2, 4, 6, 8, 
};

int cmp_uint8_t(const void* a_, const void* b_) {
	uint8_t a = *(uint8_t*)a_;
	uint8_t b = *(uint8_t*)b_;
	return a - b;
}

static const unsigned char so[257] = {
    0x2A,                                          /* [    0] OBJ_member_body */
    0x2B,                                          /* [    1] OBJ_identified_organization */
    0x04,0x00,                                     /* [    2] OBJ_etsi */
    0x04,0x00,0x7F,0x00,                           /* [    4] OBJ_etsi_identified_organization */
    0x04,0x00,0x7F,0x00,0x07,                      /* [    8] OBJ_bsi_de */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,       /* [   13] OBJ_id_PACE */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x01,  /* [   21] OBJ_id_PACE_DH_GM */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x01,0x01,  /* [   30] OBJ_id_PACE_DH_GM_3DES_CBC_CBC */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x01,0x02,  /* [   40] OBJ_id_PACE_DH_GM_AES_CBC_CMAC_128 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x01,0x03,  /* [   50] OBJ_id_PACE_DH_GM_AES_CBC_CMAC_192 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x01,0x04,  /* [   60] OBJ_id_PACE_DH_GM_AES_CBC_CMAC_256 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x02,  /* [   70] OBJ_id_PACE_ECDH_GM */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x02,0x01,  /* [   79] OBJ_id_PACE_ECDH_GM_3DES_CBC_CBC */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x02,0x02,  /* [   89] OBJ_id_PACE_ECDH_GM_AES_CBC_CMAC_128 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x02,0x03,  /* [   99] OBJ_id_PACE_ECDH_GM_AES_CBC_CMAC_192 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x02,0x04,  /* [  109] OBJ_id_PACE_ECDH_GM_AES_CBC_CMAC_256 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x03,  /* [  119] OBJ_id_PACE_DH_IM */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x03,0x01,  /* [  128] OBJ_id_PACE_DH_IM_3DES_CBC_CBC */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x03,0x02,  /* [  138] OBJ_id_PACE_DH_IM_AES_CBC_CMAC_128 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x03,0x03,  /* [  148] OBJ_id_PACE_DH_IM_AES_CBC_CMAC_192 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x03,0x04,  /* [  158] OBJ_id_PACE_DH_IM_AES_CBC_CMAC_256 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x04,  /* [  168] OBJ_id_PACE_ECDH_IM */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x04,0x01,  /* [  177] OBJ_id_PACE_ECDH_IM_3DES_CBC_CBC */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x04,0x02,  /* [  187] OBJ_id_PACE_ECDH_IM_AES_CBC_CMAC_128 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x04,0x03,  /* [  197] OBJ_id_PACE_ECDH_IM_AES_CBC_CMAC_192 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x04,0x04,  /* [  207] OBJ_id_PACE_ECDH_IM_AES_CBC_CMAC_256 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x06,  /* [  217] OBJ_id_PACE_ECDH_CAM */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x06,0x02,  /* [  226] OBJ_id_PACE_ECDH_CAM_AES_CBC_CMAC_128 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x06,0x03,  /* [  236] OBJ_id_PACE_ECDH_CAM_AES_CBC_CMAC_192 */
    0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x06,0x04,  /* [  246] OBJ_id_PACE_ECDH_CAM_AES_CBC_CMAC_256 */
};


typedef struct ASN__PRIMITIVE_TYPE_s {
    const uint8_t *buf;   /* Buffer with consecutive primitive encoding bytes */
    size_t size;    /* Size of the buffer */
} ASN__PRIMITIVE_TYPE_t;	/* Do not use this type directly! */

typedef ASN__PRIMITIVE_TYPE_t OBJECT_IDENTIFIER_t;

typedef struct OID_NID_s {
	OBJECT_IDENTIFIER_t oid;
	int nid;
} OID_NID_t;

#define NUM_NID 34

//TODO: this is just a list of all NIDs
//we need a list that is sorted by length, then buffer
static const OID_NID_t nid_objs[NUM_NID] = {
	{&so[0], 1, 1},
	{&so[1], 1, 2},
	{&so[2], 2, 3},
	{&so[4], 4, 4},
	{&so[8], 5, 5},
    {&so[13], 8, 6},
    {&so[21], 9, 7},
    {&so[70], 9, 12},
    {&so[119], 9, 17},
    {&so[168], 9, 22},
    {&so[217], 9, 27},
    {&so[30], 10, 8},
    {&so[40], 10, 9},
    {&so[50], 10, 10},
    {&so[60], 10, 11},
    {&so[79], 10, 13},
    {&so[89], 10, 14},
    {&so[99], 10, 15},
    {&so[109], 10, 16},
    {&so[128], 10, 18},
    {&so[138], 10, 19},
    {&so[148], 10, 20},
    {&so[158], 10, 21},
    {&so[177], 10, 23},
    {&so[187], 10, 24},
    {&so[197], 10, 25},
    {&so[207], 10, 26},
    {&so[226], 10, 28},
    {&so[236], 10, 29},
    {&so[246], 10, 30},
};

int cmp_OBJECT_IDENTIFIER_t(const void* a_, const void* b_) {
	OBJECT_IDENTIFIER_t *a = (OBJECT_IDENTIFIER_t*)a_;
	OBJECT_IDENTIFIER_t *b = (OBJECT_IDENTIFIER_t*)b_;

	printf("cmp_OID_t, size: %ld - %ld\n", a->size, b->size);

    int j = (a->size - b->size);
    if(j) return j;
    if(a->size == 0) return 0;
    return memcmp(a->buf, b->buf, a->size);

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

	res = bsearch(&nid_objs[9], nid_objs, sizeof(nid_objs)/sizeof(nid_objs[0]), sizeof(nid_objs[0]), &cmp_OBJECT_IDENTIFIER_t);
	printf("res: %p\n", res);
	if(res) {
		OID_NID_t* found = (OID_NID_t*)res;
		int idx = ((OID_NID_t*)res) - nid_objs;
		printf("Found, idx: %d, size: %ld, NID: %d\n", idx, found->oid.size, found->nid);
		for(size_t i=0; i<found->oid.size; ++i) {
			printf("%02X ", found->oid.buf[i]);
		}
		printf("\n");
		//printf("value: %d\n", *(uint8_t*)res);
	}

	return 0;
}
