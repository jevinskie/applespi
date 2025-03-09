#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#undef NDEBUG
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "applespi/detail/cwisstable.h"

typedef const char *icstr_t;

struct subsys_cat_pair_s {
    icstr_t subsystem;
    icstr_t category;
};

typedef struct subsys_cat_pair_s subsys_cat_pair_t;

CWISS_DECLARE_FLAT_HASHSET(SCPairSet, subsys_cat_pair_t);

struct consed_cstr_s {
    size_t hash;
    size_t len_w_nul;
    icstr_t cstr;
};

typedef struct consed_cstr_s consed_cstr_t;

static inline size_t kConsedCstrPolicy_hash(const void *val);

static inline void *kConsedCstrPolicy_alloc(size_t size, size_t align) {
    // printf("alloc sz: %zu align: %zu\n", size, align);
    void *p = aligned_alloc(align, size);
    // printf("alloc p: %p\n", p);
    // printf("alloc p: %p sz: %zu align: %zu\n", p, size, align);
    assert(p);
    return p;
}

static inline void kConsedCstrPolicy_free(void *val, size_t size, size_t align) {
    printf("free p: %p sz: %zu align: %zu\n", val, size, align);
    (void)size;
    (void)align;
    free(val);
}

static inline consed_cstr_t *make_consd_cstr(const char *cstr) {
    assert(cstr);
    const size_t len      = strlen(cstr);
    consed_cstr_t *ccstrp = malloc(sizeof(consed_cstr_t) + len + 1);
    assert(ccstrp);
    ccstrp->len_w_nul = len + 1;
    char *cstr_copy   = (char *)((uintptr_t)ccstrp + sizeof(consed_cstr_t));
    memcpy(cstr_copy, cstr, len + 1);
    ccstrp->cstr = cstr_copy;
    ccstrp->hash = 0;
    kConsedCstrPolicy_hash(&ccstrp);
    // printf("make_consd_cstr: val: %p &val: %p cstr: '%s' len: %zu hash: 0x%zx\n", ccstrp,
    // &ccstrp,
    //        ccstrp->cstr, ccstrp->len_w_nul, ccstrp->hash);
    return ccstrp;
}

static inline void kConsedCstrPolicy_copy(void *dst, const void *src) {
    consed_cstr_t **dccp = (consed_cstr_t **)dst;
    consed_cstr_t **sccp = (consed_cstr_t **)src;
    // printf("copy: dst: %p src: %p dst: 'n/a' src: '%s'\n", dccp, sccp, (*sccp)->cstr);
    assert(dccp);
    assert(sccp);
    assert((*sccp)->cstr);
    const size_t src_hash      = (*sccp)->hash;
    const size_t src_len_w_nul = (*sccp)->len_w_nul;
    const char *src_cstr       = (*sccp)->cstr;
    assert(strlen(src_cstr) + 1 == src_len_w_nul);
    assert((*sccp)->hash != 0);

    uintptr_t scc_u      = (uintptr_t)*sccp;
    uintptr_t scc_next_u = scc_u + sizeof(consed_cstr_t);
    uintptr_t scc_cstr_u = (uintptr_t)src_cstr;

    consed_cstr_t *new_ccstr = malloc(sizeof(consed_cstr_t) + src_len_w_nul);
    assert(new_ccstr);
    new_ccstr->hash      = src_hash;
    new_ccstr->len_w_nul = src_len_w_nul;
    char *new_cstr       = (char *)((uintptr_t)new_ccstr + sizeof(consed_cstr_t));
    memcpy(new_cstr, src_cstr, src_len_w_nul);
    new_ccstr->cstr = new_cstr;

    *dccp = new_ccstr;
    // printf("copy: end dst: %p src: %p dst: '%s' src: '%s'\n", dccp, sccp, (*dccp)->cstr,
    //        (*sccp)->cstr);
}

static inline void kConsedCstrPolicy_dtor(void *val) {
    if (!val) {
        fprintf(stderr, "why are you trying to free void?\n");
        assert(!"don't free void weirdo");
        return;
    }
    consed_cstr_t *ccstrp = (consed_cstr_t *)val;
    // printf("dtor: val: %p cstr: '%s' len: %zu hash: 0x%zx\n", ccstrp, ccstrp->cstr,
    //        ccstrp->len_w_nul, ccstrp->hash);
    uintptr_t val_u      = (uintptr_t)val;
    uintptr_t val_next_u = val_u + sizeof(consed_cstr_t);
    uintptr_t cstr_u     = (uintptr_t)ccstrp->cstr;
    if (cstr_u != val_next_u) {
        // not a special contiguous layout
        printf("freeing non-contig consed_cstr_t: %p cstr: %p\n", ccstrp, ccstrp->cstr);
        free((void *)ccstrp->cstr);
    }
    free((void *)ccstrp);
}

static inline size_t kConsedCstrPolicy_hash(const void *val) {
    assert(val);
    consed_cstr_t *ccstr = *(consed_cstr_t **)val;
    // printf("hash: val: %p val: '%s'\n", val, ccstr->cstr);
    if (ccstr->hash != 0) {
        // printf("hash: precalc val: %p val: '%s' state: 0x%16lx\n", val, ccstr->cstr,
        // ccstr->hash);
        return ccstr->hash;
    }
    CWISS_FxHash_State state = CWISS_AbslHash_kInit;
    CWISS_FxHash_Write(&state, &ccstr->len_w_nul, sizeof(ccstr->len_w_nul));
    CWISS_FxHash_Write(&state, ccstr->cstr, ccstr->len_w_nul - 1);
    ccstr->hash = state;
    // printf("hash: full calc val: %p val: '%s' state: 0x%16lx\n", val, ccstr->cstr, state);
    return state;
}

static inline bool kConsedCstrPolicy_eq(const void *a, const void *b) {
    assert(a && b);
    consed_cstr_t **acc = (consed_cstr_t **)a;
    consed_cstr_t **bcc = (consed_cstr_t **)b;
    // printf("eq: a: %p b: %p *a: %p *b: %p &a.cstr: %p &b.cstr: %p a.cstr: '%s' b.cstr: '%s'
    // a.len: "
    //        "%zu b.len: %zu a.hash: 0x%zx b.hash: 0x%zx\n",
    //        acc, bcc, *acc, *bcc, (*acc)->cstr, (*bcc)->cstr, (*acc)->cstr, (*bcc)->cstr,
    //        (*acc)->len_w_nul, (*bcc)->len_w_nul, (*acc)->hash, (*bcc)->hash);
    assert(*acc && *bcc);
    if (acc == bcc) {
        // printf("eq: YES by identity\n");
        return true;
    }
    if (*acc == *bcc) {
        // printf("eq: YES by indirect identity\n");
        return true;
    }
    // int strcmp_res = strcmp((*acc)->cstr, (*bcc)->cstr);
    // if (!strcmp_res) {
    //     printf("eq: advise-only: YES by strcmp\n");
    // } else {
    //     printf("eq: advise-only: NO by strcmp\n");
    // }
    if ((*acc)->hash != (*bcc)->hash) {
        // printf("eq: NO by hash\n");
        return false;
    } else {
        // printf("eq: advise-only: YES by hash\n");
    }
    if ((*acc)->len_w_nul != (*bcc)->len_w_nul) {
        // printf("eq: NO by len\n");
        return false;
    } else {
        // printf("eq: advise-only: YES by len\n");
    }
    assert((*acc)->len_w_nul > 0 && (*bcc)->len_w_nul > 0);
    int memcmp_res = memcmp((*acc)->cstr, (*bcc)->cstr, (*acc)->len_w_nul - 1);
    if (!memcmp_res) {
        // printf("eq: YES by memcmp\n");
        return true;
    } else {
        // printf("eq: NO by memcmp\n");
        return false;
    }
}

CWISS_DECLARE_NODE_SET_POLICY(kConsedCstrPolicy, consed_cstr_t *,
                              (obj_copy, kConsedCstrPolicy_copy),
                              (obj_dtor, kConsedCstrPolicy_dtor),
                              (key_hash, kConsedCstrPolicy_hash), (key_eq, kConsedCstrPolicy_eq));
//   (alloc_alloc, kConsedCstrPolicy_alloc),
//   (alloc_free, kConsedCstrPolicy_free));

CWISS_DECLARE_HASHSET_WITH(ConsedCstrSet, consed_cstr_t *, kConsedCstrPolicy);

static inline size_t ConsedCstrSet_cstr_hash(const char *self) {
    assert(self);
    CWISS_FxHash_State state = CWISS_AbslHash_kInit;
    const size_t len_w_nul   = strlen(self) + 1;
    CWISS_FxHash_Write(&state, &len_w_nul, sizeof(len_w_nul));
    CWISS_FxHash_Write(&state, self, len_w_nul - 1);
    return state;
}

static inline bool ConsedCstrSet_cstr_eq(const char *self, consed_cstr_t *const *that) {
    assert(self && that);
    assert(*that);
    assert((*that)->cstr);
    return !strcmp(self, (*that)->cstr);
}

CWISS_DECLARE_LOOKUP_NAMED(ConsedCstrSet, cstr, char);

static inline icstr_t inter_string_to_set(ConsedCstrSet *set, const char *cstr) {
    assert(set);
    assert(cstr);
    const char *interned_cstr = NULL;
    consed_cstr_t *ccstr      = NULL;
    consed_cstr_t **ccstrp    = NULL;
    ConsedCstrSet_Insert ins  = ConsedCstrSet_deferred_insert_by_cstr(set, cstr);
    ccstrp                    = ConsedCstrSet_Iter_get(&ins.iter);
    assert(ccstrp);
    if (ins.inserted) {
        ccstr                  = make_consd_cstr(cstr);
        const size_t len_w_nul = strlen(cstr) + 1;
        memcpy((char *)ccstr->cstr, cstr, len_w_nul);
        ccstr->hash = ConsedCstrSet_cstr_hash(ccstr->cstr);
        *ccstrp     = ccstr;
    } else {
        ccstr = *ccstrp;
    }
    assert(ccstr);
    return ccstr->cstr;
}

extern ConsedCstrSet global_string_interning_set;

__attribute__((constructor)) static void init_string_interning_set(void) {
    global_string_interning_set = ConsedCstrSet_new(0);
}

static inline icstr_t inter_string(const char *cstr) {
    return inter_string_to_set(&global_string_interning_set, cstr);
}

#ifdef __cplusplus
}
#endif
