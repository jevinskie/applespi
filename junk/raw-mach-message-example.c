#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define message structure for communicating with the WindowServer
typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t descriptor;
    uint32_t id;
    uint8_t data[128];
} WindowServerMessage;

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

    printf("Successfully connected to WindowServer service (port: %u)\n", service_port);

    // Create a reply port for receiving responses
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate reply port: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), service_port);
        return 1;
    }

    // Insert a send right for the reply port
    kr = mach_port_insert_right(mach_task_self(), reply_port, reply_port, MACH_MSG_TYPE_MAKE_SEND);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to insert right for reply port: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), reply_port);
        mach_port_deallocate(mach_task_self(), service_port);
        return 1;
    }

    // Prepare a message to send
    // This is a simplified example for WindowServer communication
    WindowServerMessage send_msg = {0};

    // Set up the message header
    send_msg.header.msgh_bits =
        MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
    send_msg.header.msgh_size        = sizeof(WindowServerMessage);
    send_msg.header.msgh_remote_port = service_port;
    send_msg.header.msgh_local_port  = reply_port;
    send_msg.header.msgh_id          = 2001; // An arbitrary message ID for the WindowServer

    // Set up the message body
    send_msg.body.msgh_descriptor_count = 1;

    // Include a port descriptor (needed for some system services)
    send_msg.descriptor.name        = mach_task_self();
    send_msg.descriptor.disposition = MACH_MSG_TYPE_COPY_SEND;
    send_msg.descriptor.type        = MACH_MSG_PORT_DESCRIPTOR;

    // Include a message ID and some data
    send_msg.id = 42; // Arbitrary message ID
    strcpy((char *)send_msg.data, "Hello WindowServer");

    printf("Sending message to WindowServer...\n");
    printf("Send Length pre mach_msg: %u\n", send_msg.header.msgh_size);

    // Send the message
    kr = mach_msg(&send_msg.header,          // Message buffer
                  MACH_SEND_MSG,             // Options
                  send_msg.header.msgh_size, // Send size
                  0,                         // Receive limit
                  MACH_PORT_NULL,            // Receive port
                  MACH_MSG_TIMEOUT_NONE,     // Timeout
                  MACH_PORT_NULL);           // Notification port
    printf("Send Length post mach_msg: %u\n", send_msg.header.msgh_size);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to send message: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), reply_port);
        mach_port_deallocate(mach_task_self(), service_port);
        return 1;
    }

    printf("Message sent successfully.\n");
    printf("Waiting for response...\n");

    // Prepare a buffer for the response
    WindowServerMessage recv_msg = {0};

    // Receive a message
    kr = mach_msg(&recv_msg.header, // Message buffer
                  MACH_RCV_MSG | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                      MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT), // Options
                  0,                                                     // Send size
                  sizeof(WindowServerMessage),                           // Receive limit
                  reply_port,                                            // Receive port
                  1000,                                                  // Timeout (1 second)
                  MACH_PORT_NULL);                                       // Notification port

    if (kr == MACH_RCV_TIMEOUT) {
        printf("No response received within timeout.\n");
    } else if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Error receiving message: %s\n", mach_error_string(kr));
    } else {
        printf("Received response from port %u\n", recv_msg.header.msgh_remote_port);
        printf("Message ID: %u\n", recv_msg.id);
        printf("Length: %u\n", recv_msg.header.msgh_size);
        printf("Data: %s\n", recv_msg.data);
    }

    // Clean up
    mach_port_deallocate(mach_task_self(), reply_port);
    mach_port_deallocate(mach_task_self(), service_port);

    return 0;
}
