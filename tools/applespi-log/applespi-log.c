
#undef NDEBUG
#include <assert.h>

#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>
#include <inttypes.h>
#include <limits.h>
#include <mach/mach.h>
#include <os/log.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/qos.h>
#include <unistd.h>
#include <xpc/xpc.h>

#include "applespi/detail/consed_cstr.h"
#include "applespi/detail/cwisstable.h"

struct {
    mach_msg_kind_t a;
    mach_msg_header_t b;
    mach_msg_base_t c;
    mach_msg_descriptor_t d;
    mach_msg_bits_t e;
    mach_port_seqno_t f;
    mach_port_context_t g;
    mach_port_t h;
} dummy_for_type_import;

ConsedCstrSet global_string_interning_set;

CWISS_DECLARE_FLAT_HASHSET(SubsystemSet, icstr_t);
SubsystemSet global_subsystem_set;

__attribute__((constructor)) static void init_subsystem_set(void) {
    global_subsystem_set = SubsystemSet_new(0);
}

static inline void record_subsystem(const char *subsystem) {
    icstr_t subsystem_interned = inter_string(subsystem);
    SubsystemSet_Insert ins =
        SubsystemSet_deferred_insert(&global_subsystem_set, &subsystem_interned);
    icstr_t *cstrp = SubsystemSet_Iter_get(&ins.iter);
    assert(cstrp);
    if (ins.inserted) {
        *cstrp = subsystem_interned;
        printf("new subsystem: %s\n", subsystem);
        fflush(stdout);
    }
}

static inline void dump_subsystems(void) {
    printf("subsystems:\n");
    SubsystemSet_CIter it = SubsystemSet_citer(&global_subsystem_set);
    for (const icstr_t *p = SubsystemSet_CIter_get(&it); p != NULL;
         p                = SubsystemSet_CIter_next(&it)) {
        printf("subsystem: %s\n", *p);
    }
    printf("\n");
}

CWISS_DECLARE_FLAT_HASHSET(CategorySet, icstr_t);
CategorySet global_category_set;

__attribute__((constructor)) static void init_category_set(void) {
    global_category_set = CategorySet_new(0);
}

static inline void record_category(const char *category) {
    icstr_t category_interned = inter_string(category);
    CategorySet_Insert ins = CategorySet_deferred_insert(&global_category_set, &category_interned);
    icstr_t *cstrp         = CategorySet_Iter_get(&ins.iter);
    assert(cstrp);
    if (ins.inserted) {
        *cstrp = category_interned;
        printf("new category: %s\n", category);
        fflush(stdout);
    }
}

static inline void dump_categories(void) {
    printf("categories:\n");
    CategorySet_CIter it = CategorySet_citer(&global_category_set);
    for (const icstr_t *p = CategorySet_CIter_get(&it); p != NULL;
         p                = CategorySet_CIter_next(&it)) {
        printf("category: %s\n", *p);
    }
    printf("\n");
}

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
    // printf("event_handler obj: %p desc: '%s'\n", xpc_obj, xpc_copy_description(xpc_obj));
    const char *subsystem = NULL;
    const char *category  = NULL;
    if ((subsystem = xpc_dictionary_get_string(xpc_obj, "subsystem"))) {
        record_subsystem(subsystem);
    }
    if ((category = xpc_dictionary_get_string(xpc_obj, "category"))) {
        record_category(category);
    }
    return;
};

static void cancel_handler(xpc_object_t _Nullable xpc_obj) {
    printf("cancel_handler obj: %p desc: '%s'\n", xpc_obj, xpc_copy_description(xpc_obj));
    return;
}

static void *signal_handler = ^{
    dump_subsystems();
    dump_categories();
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
