#!/usr/bin/env python3

oids = {
    'itu_t': [0],
    'iso': [1],
    'joint_iso_itu_t': [2],
    'member_body': ['iso', 2],
    'identified_organization': ['iso', 3],
    'etsi': ['itu_t', 4, 0],
    'etsi_identified_organization': ['etsi', 127, 0],
    'bsi_de': [0, 4, 0, 127, 0, 7],
    'id_PACE': ['bsi_de', 2, 2, 4],
    'id_PACE_DH_GM': ['id_PACE', 1],
    'id_PACE_DH_GM_3DES_CBC_CBC': ['id_PACE_DH_GM', 1],
    'id_PACE_DH_GM_AES_CBC_CMAC_128': ['id_PACE_DH_GM', 2],
    'id_PACE_DH_GM_AES_CBC_CMAC_192': ['id_PACE_DH_GM', 3],
    'id_PACE_DH_GM_AES_CBC_CMAC_256': ['id_PACE_DH_GM', 4],
    'id_PACE_ECDH_GM': ['id_PACE', 2],
    'id_PACE_ECDH_GM_3DES_CBC_CBC': ['id_PACE_ECDH_GM', 1],
    'id_PACE_ECDH_GM_AES_CBC_CMAC_128': ['id_PACE_ECDH_GM', 2],
    'id_PACE_ECDH_GM_AES_CBC_CMAC_192': ['id_PACE_ECDH_GM', 3],
    'id_PACE_ECDH_GM_AES_CBC_CMAC_256': ['id_PACE_ECDH_GM', 4],
    'id_PACE_DH_IM': ['id_PACE', 3],
    'id_PACE_DH_IM_3DES_CBC_CBC': ['id_PACE_DH_IM', 1],
    'id_PACE_DH_IM_AES_CBC_CMAC_128': ['id_PACE_DH_IM', 2],
    'id_PACE_DH_IM_AES_CBC_CMAC_192': ['id_PACE_DH_IM', 3],
    'id_PACE_DH_IM_AES_CBC_CMAC_256': ['id_PACE_DH_IM', 4],
    'id_PACE_ECDH_IM': ['id_PACE', 4],
    'id_PACE_ECDH_IM_3DES_CBC_CBC': ['id_PACE_ECDH_IM', 1],
    'id_PACE_ECDH_IM_AES_CBC_CMAC_128': ['id_PACE_ECDH_IM', 2],
    'id_PACE_ECDH_IM_AES_CBC_CMAC_192': ['id_PACE_ECDH_IM', 3],
    'id_PACE_ECDH_IM_AES_CBC_CMAC_256': ['id_PACE_ECDH_IM', 4],
    'id_PACE_ECDH_CAM': ['id_PACE', 6],
    'id_PACE_ECDH_CAM_AES_CBC_CMAC_128': ['id_PACE_ECDH_CAM', 2],
    'id_PACE_ECDH_CAM_AES_CBC_CMAC_192': ['id_PACE_ECDH_CAM', 3],
    'id_PACE_ECDH_CAM_AES_CBC_CMAC_256': ['id_PACE_ECDH_CAM', 4],
}

import re
re_numeric = re.compile(r'\d+')

def numeric_arcs(oids, arcs):
    ret = []

    offset = 0
    if isinstance(arcs[0], str):
        base_oid = oids[arcs[0]]
        ret.extend(numeric_arcs(oids, base_oid))
        offset = 1

    ret.extend(arcs[offset:])
    return ret

def oid_bytes(arcs):
    ret = b''

    if len(arcs) == 0:
        return ret

    if len(arcs) == 1:
        ret += bytes([40*arcs[0]])
        return ret

    ret += bytes([40*arcs[0] + arcs[1]])

    ret += bytes(arcs[2:])

    return ret

def bytes_to_c_array(data):
    return [format(b, '#04x') for b in data]

def cmp_arcs(a, b):
    a = a[1]
    b = b[1]
    if len(a) != len(b):
        return len(a) - len(b)

    for (va, vb) in zip(a, b):
        if va != vb:
            return va - vb

    return 0

oids = {k: numeric_arcs(oids, v) for k, v in oids.items()}

from functools import cmp_to_key
sorted_oids = {k: v for k, v in sorted(oids.items(), key=cmp_to_key(cmp_arcs))}

c_offset = 0
nid_count = 0
so_data = ''
defines = '#define NID_undef 0\n'
c_offsets = {}
c_lengths = {}
for name, value in oids.items():
    #print(name, value)
    #print(num_arcs)
    #print(oid_bytes(num_arcs))

    if len(value) < 2: continue

    arc_bytes = oid_bytes(value)

    c_offsets[name] = c_offset
    c_lengths[name] = len(arc_bytes)

    nid_count += 1
    defines += f'#define NID_{name} {nid_count}\n';

    c_data = ', '.join(bytes_to_c_array(arc_bytes)) + ','
    so_data += f'    {c_data.ljust(60)} /* [{str(c_offset).rjust(5)}] NID_{name} = {nid_count} */\n'
    c_offset += len(arc_bytes)

with open('oid_nids.h', 'w') as f:
    f.write('''#ifndef PASSY_OID_NIDS_H
#define PASSY_OID_NIDS_H

#include <OBJECT_IDENTIFIER.h>

typedef struct OID_NID_s {
	OBJECT_IDENTIFIER_t oid;
	int nid;
} OID_NID_t;

''')
    f.write(f'#define NUM_NID {nid_count}\n\n')
    f.write(defines)
    f.write('''
#endif''')

with open('oid_data.h', 'w') as f:
    #TODO: make const
    f.write('#include "oid_nids.h"\n\n')
    f.write(f'static unsigned char so[{c_offset}] = {{\n{so_data}}};\n')
    f.write('\n\n')

    f.write('static const OID_NID_t obj_nids[NUM_NID] = {\n')
    for name, value in sorted_oids.items():
        if len(value) < 2: continue
        offset = c_offsets[name]
        length = c_lengths[name]
        f.write(f'    {{{{&so[{offset}], {length}}}, NID_{name}}},\n')
    f.write('};\n')
