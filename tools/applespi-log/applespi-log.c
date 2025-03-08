#include <alloca.h>
#undef NDEBUG
#include <assert.h>

#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>
#include <inttypes.h>
#include <limits.h>
#include <os/log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/qos.h>
#include <unistd.h>
#include <xpc/xpc.h>

#include "applespi/detail/cwisstable.h"

struct subsys_cat_pair_s {
    const char *subsystem;
    const char *category;
};

typedef struct subsys_cat_pair_s subsys_cat_pair_t;

CWISS_DECLARE_FLAT_HASHSET(SCPairSet, subsys_cat_pair_t);

struct consed_cstr_s {
    size_t hash;
    size_t len_w_nul;
    const char *cstr;
};

typedef struct consed_cstr_s consed_cstr_t;

static inline size_t kConsedCstrPolicy_hash(const void *val);

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
    printf("make_consd_cstr: val: %p &val: %p cstr: '%s' len: %zu hash: 0x%zx\n", ccstrp, &ccstrp,
           ccstrp->cstr, ccstrp->len_w_nul, ccstrp->hash);
    return ccstrp;
}

static inline void *kConsedCstrPolicy_alloc_noooo(size_t size, size_t align) {
    (void)align;
    printf("alloc sz: %zu align: %zu\n", size, align);
    void *p = aligned_alloc(align, size);
    printf("alloc p: %p\n", p);
    assert(p);
    return p;
}

static inline void kConsedCstrPolicy_copy(void *dst, const void *src) {
    consed_cstr_t **dccp = (consed_cstr_t **)dst;
    consed_cstr_t **sccp = (consed_cstr_t **)src;
    printf("copy: dst: %p src: %p dst: 'n/a' src: '%s'\n", dccp, sccp, (*sccp)->cstr);
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
    printf("copy: end dst: %p src: %p dst: '%s' src: '%s'\n", dccp, sccp, (*dccp)->cstr,
           (*sccp)->cstr);
}

static inline void kConsedCstrPolicy_dtor(void *val) {
    if (!val) {
        fprintf(stderr, "why are you trying to free void?\n");
        assert(!"don't free void weirdo");
        return;
    }
    consed_cstr_t *ccstrp = (consed_cstr_t *)val;
    printf("dtor: val: %p cstr: '%s' len: %zu hash: 0x%zx\n", ccstrp, ccstrp->cstr,
           ccstrp->len_w_nul, ccstrp->hash);
    uintptr_t val_u      = (uintptr_t)val;
    uintptr_t val_next_u = val_u + sizeof(consed_cstr_t);
    uintptr_t cstr_u     = (uintptr_t)ccstrp->cstr;
    if (cstr_u != val_next_u) {
        // not a special contiguous layout
        free((void *)ccstrp->cstr);
    }
    free((void *)ccstrp);
}

static inline size_t kConsedCstrPolicy_hash(const void *val) {
    consed_cstr_t *ccstr = *(consed_cstr_t **)val;
    printf("hash: val: %p val: '%s'\n", val, ccstr->cstr);
    if (ccstr->hash != 0) {
        printf("hash: precalc val: %p val: '%s' state: 0x%16lx\n", val, ccstr->cstr, ccstr->hash);
        return ccstr->hash;
    }
    CWISS_FxHash_State state = 0;
    CWISS_FxHash_Write(&state, &ccstr->len_w_nul, sizeof(ccstr->len_w_nul));
    CWISS_FxHash_Write(&state, ccstr->cstr, ccstr->len_w_nul - 1);
    ccstr->hash = state;
    printf("hash: full calc val: %p val: '%s' state: 0x%16lx\n", val, ccstr->cstr, state);
    return state;
    // return (size_t)(uintptr_t)val;
}

static inline bool kConsedCstrPolicy_eq(const void *a, const void *b) {
    assert(a && b);
    consed_cstr_t **acc = (consed_cstr_t **)a;
    consed_cstr_t **bcc = (consed_cstr_t **)b;
    printf("eq: a: %p b: %p *a: %p *b: %p &a.cstr: %p &b.cstr: %p a.cstr: '%s' b.cstr: '%s' a.len: "
           "%zu b.len: %zu a.hash: 0x%zx b.hash: 0x%zx\n",
           acc, bcc, *acc, *bcc, (*acc)->cstr, (*bcc)->cstr, (*acc)->cstr, (*bcc)->cstr,
           (*acc)->len_w_nul, (*bcc)->len_w_nul, (*acc)->hash, (*bcc)->hash);
    assert(*acc && *bcc);
    if (acc == bcc) {
        printf("eq: YES by identity\n");
        return true;
    }
    if (*acc == *bcc) {
        printf("eq: YES by indirect identity\n");
        return true;
    }
    int strcmp_res = strcmp((*acc)->cstr, (*bcc)->cstr);
    if (!strcmp_res) {
        printf("eq: advise-only: YES by strcmp\n");
    } else {
        printf("eq: advise-only: NO by strcmp\n");
    }
    if ((*acc)->hash != (*bcc)->hash) {
        printf("eq: NO by hash\n");
        return false;
    } else {
        printf("eq: advise-only: YES by hash\n");
    }
    if ((*acc)->len_w_nul != (*bcc)->len_w_nul) {
        printf("eq: NO by len\n");
        return false;
    } else {
        printf("eq: advise-only: YES by len\n");
    }
    assert((*acc)->len_w_nul > 0 && (*bcc)->len_w_nul > 0);
    int memcmp_res = memcmp((*acc)->cstr, (*bcc)->cstr, (*acc)->len_w_nul - 1);
    if (!memcmp_res) {
        printf("eq: YES by memcmp\n");
        return true;
    } else {
        printf("eq: NO by memcmp\n");
        return false;
    }
}

CWISS_DECLARE_FLAT_SET_POLICY(kConsedCstrPolicy, consed_cstr_t, (obj_copy, kConsedCstrPolicy_copy),
                              (obj_dtor, kConsedCstrPolicy_dtor),
                              (key_hash, kConsedCstrPolicy_hash), (key_eq, kConsedCstrPolicy_eq));

CWISS_DECLARE_HASHSET_WITH(ConsedCstrSet, const char *, kConsedCstrPolicy);

void *_Nonnull stream_filter_for_pid(pid_t pid, size_t *_Nullable sz) {
    // <dict>
    //     <key>pid</key> <!-- filter type -->
    //     <dict>
    //         <key>1</key> <!-- PID (as string) -->
    //         <integer>0</integer> <!-- flags -->
    //     </dict>
    // </dict>

    CFStringRef pidKey = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%d"), pid);
    assert(pidKey);
    CFNumberRef zeroFlag = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &(int){0});
    assert(zeroFlag);

    // Inner dictionary { "<pid>": 0 [, "<pid2>": <FLAGS>, ...] }
    const void *pidKeys[]   = {pidKey};
    const void *pidValues[] = {zeroFlag};
    CFDictionaryRef pidDict =
        CFDictionaryCreate(kCFAllocatorDefault, pidKeys, pidValues, 1,
                           &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    assert(pidDict);

    // Outer dictionary { "pid": { "<pid>": 0 } }
    const void *rootKeys[]   = {CFSTR("pid")};
    const void *rootValues[] = {pidDict};
    CFDictionaryRef rootDict =
        CFDictionaryCreate(kCFAllocatorDefault, rootKeys, rootValues, 1,
                           &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    assert(rootDict);

    CFDataRef plistData = CFPropertyListCreateData(kCFAllocatorDefault, rootDict,
                                                   kCFPropertyListBinaryFormat_v1_0, 0, NULL);
    assert(plistData);

    CFRelease(pidKey);
    CFRelease(zeroFlag);
    CFRelease(pidDict);
    CFRelease(rootDict);

    const size_t plistBufSz = CFDataGetLength(plistData);
    assert(plistBufSz);
    void *plistBuf = malloc(CFDataGetLength(plistData));
    assert(plistBuf);
    memcpy(plistBuf, CFDataGetBytePtr(plistData), plistBufSz);
    CFRelease(plistData);

    if (sz) {
        *sz = plistBufSz;
    }

    return plistBuf; // free me
}

static void connection_handler(xpc_connection_t xpc_con) {
    printf("connection_handler conn: %p desc: '%s'\n", xpc_con, xpc_copy_description(xpc_con));
    return;
}

static void *event_handler = ^(xpc_object_t _Nonnull xpc_obj) {
    printf("event_handler obj: %p desc: '%s'\n", xpc_obj, xpc_copy_description(xpc_obj));
    return;
};

static void cancel_handler(xpc_object_t _Nullable xpc_obj) {
    printf("cancel_handler obj: %p desc: '%s'\n", xpc_obj, xpc_copy_description(xpc_obj));
    return;
}

static void *signal_handler = ^{
    fflush(stdout);
    printf("dispatch signal cancel exit\n");
    fflush(stdout);
    exit(0);
};

int main(int argc, const char **argv) {
    if (argc != 2) {
        printf("bad args\n");
        return 1;
    }
    const dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    const dispatch_source_t signal_source =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, queue);
    dispatch_source_set_event_handler(signal_source, signal_handler);
    dispatch_resume(signal_source);

    pid_t pid = atoi(argv[1]);
    // os_log_t logger = os_log_create("vin.je.applespi-log", "applespi-log-cat");
    // os_log(logger, "test before pid: %{public}d", pid);

    ConsedCstrSet set = ConsedCstrSet_new(8);

    for (int i = 0; i < 8; ++i) {
        int val = i * i + 1;
        char str[32];
        snprintf(str, sizeof(str), "%d", val);
        const char *cstr     = (const char *)str;
        consed_cstr_t *ccstr = make_consd_cstr(cstr);
        printf("adding str %p aka '%s'\n", ccstr, ccstr->cstr);
        // ConsedCstrSet_dump(&set);
        ConsedCstrSet_insert(&set, &ccstr);
    }
    for (int i = 2000; i < 2000 + 8; ++i) {
        int val = i;
        char str[32];
        snprintf(str, sizeof(str), "%d", val);
        const char *cstr     = (const char *)str;
        consed_cstr_t *ccstr = make_consd_cstr(cstr);
        printf("adding2 str %p aka '%s'\n", ccstr, ccstr->cstr);
        // ConsedCstrSet_dump(&set);
        ConsedCstrSet_insert(&set, &ccstr);
    }
    for (int i = 2000; i < 2000 + 8; ++i) {
        int val = i;
        char str[32];
        snprintf(str, sizeof(str), "%d", val);
        const char *cstr     = (const char *)str;
        consed_cstr_t *ccstr = make_consd_cstr(cstr);
        printf("adding3 str %p aka '%s'\n", ccstr, ccstr->cstr);
        // ConsedCstrSet_dump(&set);
        ConsedCstrSet_insert(&set, &cstr);
    }
    // ConsedCstrSet_dump(&set);
    consed_cstr_t *ccstrptrs[3000] = {};
    printf("entries:\n");
    size_t idx            = 0;
    ConsedCstrSet_Iter it = ConsedCstrSet_iter(&set);
    for (consed_cstr_t *p = ConsedCstrSet_Iter_get(&it); p != NULL;
         p                = ConsedCstrSet_Iter_next(&it)) {
        printf("p: %p '%s' len: %zu hash: 0x%zx\n", p, p->cstr, p->len_w_nul, p->hash);
        ccstrptrs[idx++] = p;
    }
    size_t num_strptrs = idx;
    idx                = 0;
    printf("\n");

    for (size_t i = 0; i < num_strptrs; ++i) {
        consed_cstr_t *ccstr = ccstrptrs[i];
        printf("adding4 p: %p &p: %p '%s' len: %zu hash: 0x%zx\n", ccstr, &ccstr, ccstr->cstr,
               ccstr->len_w_nul, ccstr->hash);
        ConsedCstrSet_insert(&set, &ccstr);
    }

    printf("entries after:\n");
    it = ConsedCstrSet_iter(&set);
    for (consed_cstr_t *p = ConsedCstrSet_Iter_get(&it); p != NULL;
         p                = ConsedCstrSet_Iter_next(&it)) {
        printf("p: %p '%s' len: %zu hash: 0x%zx\n", p, p->cstr, p->len_w_nul, p->hash);
        ccstrptrs[idx++] = p;
    }
    printf("\n");

    printf("ConsedCstrSet test done\n");
    exit(0);

    const xpc_connection_t xpc_con =
        xpc_connection_create_mach_service("com.apple.diagnosticd", DISPATCH_TARGET_QUEUE_DEFAULT,
                                           XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    printf("xpc_con: %p\n", xpc_con);
    xpc_connection_set_event_handler(xpc_con, event_handler);
    xpc_connection_set_finalizer_f(xpc_con, cancel_handler);
    xpc_connection_set_target_queue(xpc_con, queue);
    xpc_connection_activate(xpc_con);
    const xpc_object_t start_req = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(start_req, "action", 3);
    xpc_dictionary_set_uint64(start_req, "flags", 0x800 | 0x2 | 0x1);
    xpc_dictionary_set_uint64(start_req, "types", 8);
    if (pid == -2) {
        pid = getpid();
    }
    if (pid >= 0) {
        size_t filter_sz    = 0;
        uint8_t *filter_buf = stream_filter_for_pid(pid, &filter_sz);
        assert(filter_buf);
        assert(filter_sz);
        for (size_t i = 0; i < filter_sz; ++i) {
            printf("%02hhx\n", filter_buf[i]);
        }
        xpc_dictionary_set_data(start_req, "stream_filter", filter_buf, filter_sz);
        free(filter_buf);
    }
    printf("con_send_obj obj: %p desc: '%s'\n", start_req, xpc_copy_description(start_req));
    // dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1000000000),
    // dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{ os_log(logger, "test after 1 second
    // %{public}zu", sizeof(start_req));
    // });
    xpc_connection_send_message(xpc_con, start_req);
    dispatch_main();
    // while (true) {
    //     usleep(100);
    // }
    fflush(stdout);
    printf("post dispatch_main()\n");
    fflush(stdout);
    return EXIT_FAILURE;
}
