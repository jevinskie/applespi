#undef NDEBUG
#include <assert.h>

#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <xpc/xpc.h>

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

    uint8_t pid_filter_bplist[63] = {0x62, 0x70, 0x6C, 0x69, 0x73, 0x74, 0x30, 0x30, 0xD1, 0x01,
                                     0x02, 0x53, 0x70, 0x69, 0x64, 0xd1, 0x03, 0x04, 0x50};
    const size_t pid_decimal_ascii_sz_off = 18;
    const size_t pid_decimal_ascii_off    = 19;

    size_t num_digits = 0;
    pid_t tpid        = pid;
    while (tpid) {
        tpid /= 10;
        ++num_digits;
    }
    assert(num_digits <= 0xF);
    printf("num_digits: %zu\n", num_digits);
    pid_filter_bplist[pid_decimal_ascii_sz_off] |= num_digits;
    tpid = pid;
    for (size_t i = 0; i < num_digits; ++i) {
        uint8_t d                                                     = tpid % 10;
        pid_filter_bplist[pid_decimal_ascii_off + num_digits - 1 - i] = '0' + d;
        tpid /= 10;
    }
    const size_t trailer_off                        = pid_decimal_ascii_off + num_digits;
    pid_filter_bplist[trailer_off]                  = 0x10;
    pid_filter_bplist[trailer_off + 1]              = 0x00;
    pid_filter_bplist[trailer_off + 2]              = 0x08;
    pid_filter_bplist[trailer_off + 3]              = 0x0b;
    pid_filter_bplist[trailer_off + 4]              = 0x0f;
    pid_filter_bplist[trailer_off + 5]              = 0x12;
    pid_filter_bplist[trailer_off + 6]              = 0x13 + num_digits;
    pid_filter_bplist[trailer_off + 6 + 6 + 1 + 0]  = 0x01;
    pid_filter_bplist[trailer_off + 6 + 6 + +1 + 1] = 0x01;
    // pid_filter_bplist[trailer_off + 6 + 6 + 2] = 0x01;
    pid_filter_bplist[trailer_off + 6 + 6 + 3 + 7] = 0x05;
    // pid_filter_bplist[trailer_off + 6 + 6 + 4 + 7] = 0x00;
    pid_filter_bplist[trailer_off + 6 + 6 + 5 + 7 + 14] = trailer_off + 2;
    const size_t pid_filter_bplist_sz                   = trailer_off + 6 + 6 + 5 + 7 + 15;
    printf("pid_filter_bplist_sz: %zu\n", pid_filter_bplist_sz);
    for (size_t i = 0; i < pid_filter_bplist_sz; ++i) {
        printf("%02hhx\n", pid_filter_bplist[i]);
    }

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

    printf("con_send_obj obj: %p desc: '%s'\n", start_req, xpc_copy_description(start_req));
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
