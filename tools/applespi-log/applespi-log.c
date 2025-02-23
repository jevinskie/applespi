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

int main(void) {
    const dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    const dispatch_source_t signal_source =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, queue);
    dispatch_source_set_event_handler(signal_source, signal_handler);
    dispatch_resume(signal_source);

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
