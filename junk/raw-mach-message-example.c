#include <mach/message.h>
#include <sys/_types/_mach_port_t.h>
#undef NDEBUG
#include <assert.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define message structure for communicating with the WindowServer
typedef struct {
    mach_msg_header_t header;
    mach_port_t server_port_maybe;
} SkylightReq;

_Static_assert(sizeof(SkylightReq) == 28, "req msg size");

typedef struct {
    mach_msg_header_t header;
    NDR_record_t ndr;
    uint32_t ver_major;
    uint32_t ver_minor;
    mach_msg_body_t body;
    mach_msg_body_t body_pad;
    mach_msg_body_t body_pad_pad;
    mach_msg_port_descriptor_t send_port;
    uint32_t login;
    mach_msg_security_trailer_t trailer;
} SkylightResp;

_Static_assert(sizeof(SkylightResp) == 88, "resp msg size");

typedef union {
    SkylightReq req;
    SkylightResp resp;
} SkylightMsg;

int main(int argc, const char *argv[]) {
    kern_return_t kr;
    mach_port_t bootstrap_port;
    mach_port_t service_port;
    mach_port_t reply_port;

    printf("Starting raw Mach message example...\n");

    // Get the bootstrap port for the current task
    task_get_bootstrap_port(mach_task_self(), &bootstrap_port);

    // Look up the WindowServer service
    // This is a system service that should be accessible even in sandboxed apps
    kr = bootstrap_look_up(bootstrap_port, "com.apple.windowserver", &service_port);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to look up WindowServer service: %s\n", mach_error_string(kr));
        return 1;
    }

    printf("Successfully connected to WindowServer service (port: 0x%08x %u)\n", service_port,
           service_port);

    // Create a reply port for receiving responses
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate reply port: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), service_port);
        return 1;
    }
    printf("reply_port: 0x%08x %u\n", reply_port, reply_port);

    // Insert a send right for the reply port
    kr = mach_port_insert_right(mach_task_self(), reply_port, reply_port, MACH_MSG_TYPE_MAKE_SEND);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to insert right for reply port: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), reply_port);
        mach_port_deallocate(mach_task_self(), service_port);
        return 1;
    }

    mach_port_t hot_reply_port = mig_get_reply_port();
    printf("hot_reply_port: 0x%08x %u\n", hot_reply_port, hot_reply_port);
    assert(hot_reply_port != MACH_PORT_NULL);

    // Prepare a message to send
    // This is a simplified example for WindowServer communication
    SkylightMsg send_msg = {};
    memset(&send_msg, 0, sizeof(send_msg));

    // Set up the message header
    send_msg.req.header.msgh_bits =
        MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
    send_msg.req.header.msgh_size        = sizeof(send_msg.req);
    send_msg.req.header.msgh_remote_port = service_port;
    send_msg.req.header.msgh_local_port  = hot_reply_port;
    send_msg.req.header.msgh_id          = 29000; // get version

    // Set up the message body
    // send_msg.body.msgh_descriptor_count = 1;

    // Include a port descriptor (needed for some system services)
    // send_msg.descriptor.name        = mach_task_self();
    // send_msg.descriptor.disposition = MACH_MSG_TYPE_COPY_SEND;
    // send_msg.descriptor.type        = MACH_MSG_PORT_DESCRIPTOR;

    // Include a message ID and some data
    // send_msg.id = 42; // Arbitrary message ID
    // strcpy((char *)send_msg.data, "Hello WindowServer");

    printf("Sending message to WindowServer...\n");
    printf("Send bits pre mach_msg: 0x%08x\n", send_msg.req.header.msgh_bits);
    printf("Send Length pre mach_msg: %u\n", send_msg.req.header.msgh_size);

    mach_port_t cool_reply_port = mig_get_reply_port();
    printf("cool_reply_port: 0x%08x %u\n", cool_reply_port, cool_reply_port);
    assert(cool_reply_port != MACH_PORT_NULL);

    // Send the message
    kr = mach_msg(&send_msg.req.header, // Message buffer
                  MACH_SEND_MSG | MACH_RCV_MSG | MACH_SEND_TIMEOUT | MACH_RCV_TIMEOUT, // Options
                  sizeof(send_msg.req),  // Send size - must be >= 28
                  sizeof(send_msg.resp), // Receive limit
                  hot_reply_port,        // Receive port
                  1000,                  // Timeout
                  MACH_PORT_NULL);       // Notification port
    printf("Send bits post mach_msg: 0x%08x\n", send_msg.req.header.msgh_bits);
    printf("Send Length post mach_msg: %u\n", send_msg.req.header.msgh_size);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to send phase A message: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), reply_port);
        mach_port_deallocate(mach_task_self(), service_port);
        return 1;
    }

    printf("Message sent successfully.\n");
    printf("Waiting for response...\n");

    // Prepare a buffer for the response
    SkylightMsg recv_msg = {};
    memset(&recv_msg, 0, sizeof(recv_msg));

    // Receive a message
    kr = mach_msg(&recv_msg.resp.header, // Message buffer
                  MACH_RCV_MSG | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                      MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT), // Options
                  0,                                                     // Send size
                  sizeof(recv_msg.resp), // Receive limit - must be >= 88
                  reply_port,            // Receive port
                  1000,                  // Timeout (1 second)
                  MACH_PORT_NULL);       // Notification port

    if (kr == MACH_RCV_TIMEOUT) {
        printf("No response received within timeout.\n");
    } else if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Error receiving phase B message: %s\n", mach_error_string(kr));
    } else {
        printf("Received response from port 0x%08x %u\n", recv_msg.resp.header.msgh_remote_port,
               recv_msg.resp.header.msgh_remote_port);
        printf("Length: %u\n", recv_msg.resp.header.msgh_size);
    }

    // Clean up
    mach_port_deallocate(mach_task_self(), reply_port);
    mach_port_deallocate(mach_task_self(), service_port);

    return 0;
}
