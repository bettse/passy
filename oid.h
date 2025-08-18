#ifndef PASSY_OID_H
#define PASSY_OID_H

#include <OBJECT_IDENTIFIER.h>

#include "oid_nids.h"

//void* bsearch(const void* key, const void* base0, size_t nmemb, size_t size, int (*compar)(const void*, const void*)) const void* key;

int oid_oid2nid(OBJECT_IDENTIFIER_t *oid);

#endif
