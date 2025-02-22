#include <stdio.h>
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>

#include <dispatch/dispatch.h>
#include <xpc/xpc.h>

static uint64_t g_ctx;

static void connection_handler(xpc_connection_t xpc_con) {
    printf("connection_handler conn: %p desc: '%s'\n", xpc_con, xpc_copy_description(xpc_con));
    return;
}

static void event_handler(xpc_object_t _Nonnull xpc_obj) {
    printf("event_handler obj: %p desc: '%s'\n", xpc_obj, xpc_copy_description(xpc_obj));
    return;
}

static void cancel_handler(xpc_object_t _Nullable xpc_obj) {
    printf("cancel_handler obj: %p desc: '%s'\n", xpc_obj, xpc_copy_description(xpc_obj));
    return;
}

int main(void) {
    const dispatch_queue_t queue          = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    const dispatch_source_t signal_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, queue);
    dispatch_source_set_event_handler(signal_source, ^{
        printf("dispatch signal cancel exit\n");
        fflush(stdout);
        exit(0);
    });
    dispatch_resume(signal_source);

    xpc_connection_t xpc_con = xpc_connection_create_mach_service(
        "com.apple.diagnosticd", DISPATCH_TARGET_QUEUE_DEFAULT, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    printf("xpc_con: %p\n", xpc_con);
    printf("&g_ctx: %p\n", &g_ctx);
    xpc_connection_set_event_handler(xpc_con, ^(xpc_object_t o) { event_handler(o); });
    xpc_connection_set_context(xpc_con, &g_ctx);
    xpc_connection_set_finalizer_f(xpc_con, cancel_handler);
    xpc_connection_set_target_queue(xpc_con, queue);
    xpc_connection_activate(xpc_con);
    xpc_object_t req = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(req, "action", 3);
    xpc_dictionary_set_uint64(req, "flags", 3);
    xpc_dictionary_set_uint64(req, "types", 0x8 | 0x4 | 0x2 | 0x1);

    printf("con_send_obj obj: %p desc: '%s'\n", req, xpc_copy_description(req));
    xpc_connection_send_message_with_reply(xpc_con, req, queue, ^(xpc_object_t o) { event_handler(o); });
    dispatch_main();
    printf("post dispatch_main()\n");
    fflush(stdout);
    return EXIT_FAILURE;
}
