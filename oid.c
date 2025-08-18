#include "oid.h"
#include "oid_data.h"

int cmp_OBJECT_IDENTIFIER_t(const void* a_, const void* b_) {
    OBJECT_IDENTIFIER_t* a = (OBJECT_IDENTIFIER_t*)a_;
    OBJECT_IDENTIFIER_t* b = (OBJECT_IDENTIFIER_t*)b_;

    //printf("cmp_OID_t, size: %ld - %ld\n", a->size, b->size);

    int j = (a->size - b->size);
    if(j) return j;
    if(a->size == 0) return 0;
    return memcmp(a->buf, b->buf, a->size);
}

int oid_oid2nid(OBJECT_IDENTIFIER_t* oid) {
    void* res = bsearch(
        oid,
        obj_nids,
        sizeof(obj_nids) / sizeof(obj_nids[0]),
        sizeof(obj_nids[0]),
        &cmp_OBJECT_IDENTIFIER_t);
    // printf("res: %p\n", res);
    if(res) {
        OID_NID_t* found = (OID_NID_t*)res;
        // int idx = ((OID_NID_t*)res) - obj_nids;
        // printf("Found, idx: %d, size: %zu, NID: %d\n", idx, found->oid.size, found->nid);
        // for(size_t i=0; i<found->oid.size; ++i) {
        // 	printf("%02X ", found->oid.buf[i]);
        // }
        // printf("\n");
        return found->nid;
    }

    return NID_undef;
}
