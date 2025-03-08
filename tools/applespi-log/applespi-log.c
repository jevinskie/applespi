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

static inline void kConsedCstrPolicy_copy(void *dst, const void *src) {
    const char **d = (const char **)dst;
    const char **s = (const char **)src;
    printf("copy: dst: %p src: %p dst: 'n/a' src: '%s'\n", d, s, *s);
    assert(src);
    assert(dst);
    // assert(*d);
    assert(*s);
    const char *src_cstr = *s;
    const size_t bytesz  = strlen(src_cstr) + 1;
    char *dst_cstr       = malloc(bytesz);
    printf("copy strlen %zu str: '%s' new malloc: %p\n", bytesz, src_cstr, dst_cstr);
    assert(dst_cstr);
    memcpy(dst_cstr, src_cstr, bytesz);
    // *(char **)dst = dst_cstr;
    *d = dst_cstr;
    printf("copy end: dst: %p src: %p dst: '%s' src: '%s'\n", dst, src, *d, *s);
}

static inline void kConsedCstrPolicy_dtor(void *val) {
    printf("dtor: val: %p val: '%s'\n", val, (char *)val);
    assert(val);
    free(val);
}

static inline size_t kConsedCstrPolicy_hash(const void *val) {
    printf("hash: val: %p val: '%s'\n", val, *(char **)val);
    const char *cstr         = *(const char **)val;
    CWISS_FxHash_State state = 0;
    const size_t len         = strlen(cstr);
    CWISS_FxHash_Write(&state, &len, sizeof(len));
    CWISS_FxHash_Write(&state, cstr, len);
    printf("hash: val: %p val: '%s' state: 0x%16lx\n", val, *(char **)val, state);
    return state;
    // return (size_t)(uintptr_t)val;
}

static inline bool kConsedCstrPolicy_eq(const void *a, const void *b) {
    assert(a && b);
    const char **ac = (const char **)a;
    const char **bc = (const char **)b;
    printf("eq: a: %p b: %p a: *a: %p *b: %p a: '%s' b: '%s'\n", a, b, *ac, *bc, *ac, *bc);
    assert(*ac && *bc);
    if (ac == bc) {
        printf("eq: YES by identity\n");
        return true;
    }
    if (*ac == *bc) {
        printf("eq: YES by indirect identity\n");
        return true;
    }
    int differ = strcmp(*ac, *bc);
    if (!differ) {
        printf("eq: YES by strcmp\n");
    } else {
        printf("eq: NO by strcmp\n");
    }
    return !differ;
}

CWISS_DECLARE_FLAT_SET_POLICY(kConsedCstrPolicy, char *, (obj_copy, kConsedCstrPolicy_copy),
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
        const char *cstr = (const char *)str;
        printf("adding str %p aka '%s'\n", cstr, cstr);
        // ConsedCstrSet_dump(&set);
        ConsedCstrSet_insert(&set, &cstr);
    }
    for (int i = 2000; i < 2000 + 8; ++i) {
        int val = i;
        char str[32];
        snprintf(str, sizeof(str), "%d", val);
        const char *cstr = (const char *)str;
        printf("adding2 str %p aka '%s'\n", cstr, cstr);
        // ConsedCstrSet_dump(&set);
        ConsedCstrSet_insert(&set, &cstr);
    }
    for (int i = 2000; i < 2000 + 8; ++i) {
        int val = i;
        char str[32];
        snprintf(str, sizeof(str), "%d", val);
        const char *cstr = (const char *)str;
        printf("adding2 str %p aka '%s'\n", cstr, cstr);
        // ConsedCstrSet_dump(&set);
        ConsedCstrSet_insert(&set, &cstr);
    }
    // ConsedCstrSet_dump(&set);
    const char *strptrs[3000] = {};
    printf("entries:\n");
    size_t idx            = 0;
    ConsedCstrSet_Iter it = ConsedCstrSet_iter(&set);
    for (const char **p = ConsedCstrSet_Iter_get(&it); p != NULL;
         p              = ConsedCstrSet_Iter_next(&it)) {
        printf("'%s'\n", *p);
        printf("p: %p *p: %p *p: '%s'\n", p, *p, *p);
        strptrs[idx++] = *p;
    }
    size_t num_strptrs = idx;
    idx                = 0;
    printf("\n");

    for (size_t i = 0; i < num_strptrs; ++i) {
        const char *consed_cstr = strptrs[i];
        printf("adding3 str %p &str %p aka '%s'\n", consed_cstr, &consed_cstr, consed_cstr);
        ConsedCstrSet_insert(&set, &consed_cstr);
    }

    printf("entries after:\n");
    it = ConsedCstrSet_iter(&set);
    for (const char **p = ConsedCstrSet_Iter_get(&it); p != NULL;
         p              = ConsedCstrSet_Iter_next(&it)) {
        printf("p: %p *p: %p *p: '%s'\n", p, *p, *p);
    }
    printf("\n");

    printf("ConsedCstrSet test done");

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
