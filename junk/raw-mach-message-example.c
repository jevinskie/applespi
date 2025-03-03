#include <_types/_uint32_t.h>
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

// https://gist.github.com/ccbrown/9722406
__attribute__((unused)) static void hexdump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

__attribute__((unused)) static void hexdump32(const uint32_t *buf, size_t count) {
    const void *data  = buf;
    const size_t size = count * sizeof(uint32_t);
    char ascii[17];
    size_t i, j, w;
    ascii[16] = '\0';
    for (w = 0; w < count; ++w) {
        printf("%08x ", buf[w]);
        for (i = w * sizeof(uint32_t); i < (w + 1) * sizeof(uint32_t); ++i) {
            if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
                ascii[i % 16] = ((unsigned char *)data)[i];
            } else {
                ascii[i % 16] = '.';
            }
        }
        if ((w + 1) % 2 == 0 || w + 1 == count) {
            printf(" ");
            if ((w + 1) % 4 == 0) {
                printf("|  %s \n", ascii);
            } else if (w + 1 == count) {
                ascii[((w + 1) * sizeof(uint32_t)) % 16] = '\0';
                if ((w + 1) % 4 <= 2) {
                    printf("   ");
                }
                for (j = (w + 1) % 4; j < 4; ++j) {
                    printf("        ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

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
        return 1;
    }
    printf("reply_port: 0x%08x %u\n", reply_port, reply_port);

    // Insert a send right for the reply port
    kr = mach_port_insert_right(mach_task_self(), reply_port, reply_port, MACH_MSG_TYPE_MAKE_SEND);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to insert right for reply port: %s\n", mach_error_string(kr));
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
    printf("send_msg.ver_major %u ver_minor: %u\n", send_msg.resp.ver_major,
           send_msg.resp.ver_minor);
    printf("resp: sz: %u\n", send_msg.resp.header.msgh_size);
    hexdump(&send_msg.resp, sizeof(send_msg.resp));
    assert(sizeof(send_msg.resp) % sizeof(uint32_t) == 0);
    hexdump32((uint32_t *)&send_msg.resp, sizeof(send_msg.resp) / sizeof(uint32_t));

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to send phase A message: %s\n", mach_error_string(kr));
        return 1;
    }

    printf("Message sent successfully.\n");

    return 0;
}
