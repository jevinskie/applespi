#include <_types/_uint32_t.h>
#include <mach/message.h>
#undef NDEBUG
#include <assert.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
} mig_reply_error_duplicate_for_reference_t;

// Define message structure for communicating with the WindowServer
typedef struct {
    mach_msg_header_t head;
} SkylightReq;

_Static_assert(sizeof(SkylightReq) == 24, "req msg size");

// bad MIG_BAD_ARGUMENTS if COMPLEX (high bit) or size != 24
// 00001100 00000024  00000000 00000707  |  ....$...........
// 00000000 000071ac  00000000 00000001  |  .....q..........
// fffffed0 00000000  00000008 00000000  |  ................
// 00000000 00000000  00000000 00000000  |  ................
// 00000000 00000000  00000000 00000000  |  ................
// 00000000 00000000                     |  ........

// better? retcode 0 but resp sz = 60? not 88
// 80001100 0000003c  00000000 00000707  |  ....<...........
// 00000000 000071ac  00000001 00000c03  |  .....q..........
// 00000000 00110000  00000000 00000001  |  ................
// 00000258 00000000  aaaaaa01 00000000  |  X...............
// 00000008 00000000  00000000 00000000  |  ................
// 00000000 00000000                     |  ........

typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t session_port;
    NDR_record_t ndr;
    uint32_t ver_major;
    uint32_t ver_minor;
    uint8_t login;
    uint8_t login_pad[3];
    mach_msg_audit_trailer_t trailer;
} SkylightResp;

_Static_assert(sizeof(SkylightResp) == 68 + sizeof(mach_port_seqno_t) + sizeof(security_token_t) +
                                           sizeof(audit_token_t),
               "resp msg size");

typedef union {
    SkylightReq req;
    SkylightResp resp;
} SkylightMsg;

static void dump_msg_body(const mach_msg_body_t *body) {
    printf("mach_msg_body_t @ %p\n", body);
    printf("    msgh_descriptor_count: %u\n", body->msgh_descriptor_count);
    fflush(stdout);
}

static void dump_msg_port_desc(const mach_msg_port_descriptor_t *desc) {
    printf("mach_msg_port_descriptor_t @ %p\n", desc);
    printf("    name: 0x%08x %u\n", desc->name, desc->name);
    printf("    pad1: %u\n", desc->pad1);
    printf("    pad2: %u\n", desc->pad2);
    printf("    disposition: %u\n", desc->disposition);
    printf("    type: %u\n", desc->type);
    fflush(stdout);
}

static void dump_msg_audit_trailer(const mach_msg_audit_trailer_t *trailer) {
    printf("mach_msg_audit_trailer_t @ %p\n", trailer);
    printf("mach_msg_trailer_type_t  msgh_trailer_type: 0x%08x\n", trailer->msgh_trailer_type);
    printf("mach_msg_trailer_size_t  msgh_trailer_size: 0x%08x %u\n", trailer->msgh_trailer_size,
           trailer->msgh_trailer_size);
    printf("mach_port_seqno_t        msgh_seqno: 0x%08x %u\n", trailer->msgh_seqno,
           trailer->msgh_seqno);
    printf("security_token_t         msgh_sender: @ %p\n", &trailer->msgh_sender);
    printf("security_token_t             msgh_sender[0]: UID 0x%08x %u\n",
           trailer->msgh_sender.val[0], trailer->msgh_sender.val[0]);
    printf("security_token_t             msgh_sender[1]: GID 0x%08x %u\n",
           trailer->msgh_sender.val[1], trailer->msgh_sender.val[1]);
    printf("audit_token_t            msgh_audit: @ %p\n", &trailer->msgh_audit);
    printf("audit_token_t                msgh_audit[0]: AuditUID 0x%08x %u\n",
           trailer->msgh_audit.val[0], trailer->msgh_audit.val[0]);
    printf("audit_token_t                msgh_audit[1]: EUID 0x%08x %u\n",
           trailer->msgh_audit.val[1], trailer->msgh_audit.val[1]);
    printf("audit_token_t                msgh_audit[2]: EGID 0x%08x %u\n",
           trailer->msgh_audit.val[2], trailer->msgh_audit.val[2]);
    printf("audit_token_t                msgh_audit[3]: RUID 0x%08x %u\n",
           trailer->msgh_audit.val[3], trailer->msgh_audit.val[3]);
    printf("audit_token_t                msgh_audit[4]: RGID 0x%08x %u\n",
           trailer->msgh_audit.val[4], trailer->msgh_audit.val[4]);
    printf("audit_token_t                msgh_audit[5]: PID 0x%08x %u\n",
           trailer->msgh_audit.val[5], trailer->msgh_audit.val[5]);
    printf("audit_token_t                msgh_audit[6]: AuditSessionID 0x%08x %u\n",
           trailer->msgh_audit.val[6], trailer->msgh_audit.val[6]);
    printf("audit_token_t                msgh_audit[7]: PID Version 0x%08x %u\n",
           trailer->msgh_audit.val[7], trailer->msgh_audit.val[7]);
    fflush(stdout);
}

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
                    printf(" ");
                    if ((w + 1) % 4 != 2) {
                        printf("  ");
                    }
                }
                for (j = (w + 1) % 4; j < 4; ++j) {
                    printf("         ");
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
    send_msg.req.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
    send_msg.req.head.msgh_size = sizeof(send_msg.req);
    send_msg.req.head.msgh_remote_port = service_port;
    send_msg.req.head.msgh_local_port  = hot_reply_port;
    send_msg.req.head.msgh_id          = 29000; // get version

    printf("Sending message to WindowServer...\n");
    printf("Send bits pre mach_msg: 0x%08x\n", send_msg.req.head.msgh_bits);
    printf("Send Length pre mach_msg: %u\n", send_msg.req.head.msgh_size);

    mach_port_t cool_reply_port = mig_get_reply_port();
    printf("cool_reply_port: 0x%08x %u\n", cool_reply_port, cool_reply_port);
    assert(cool_reply_port != MACH_PORT_NULL);

    printf("req: sz: %u sizeof(): %zu\n", send_msg.req.head.msgh_size, sizeof(send_msg.req));
    hexdump(&send_msg.req, sizeof(send_msg.req));
    assert(sizeof(send_msg.req) % sizeof(uint32_t) == 0);
    hexdump32((uint32_t *)&send_msg.req, sizeof(send_msg.req) / sizeof(uint32_t));

    // Send the message
    kr = mach_msg(&send_msg.req.head, // Message buffer
                  MACH_SEND_MSG | MACH_RCV_MSG | MACH_SEND_TIMEOUT | MACH_RCV_TIMEOUT |
                      MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                      MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT), // Options
                  sizeof(send_msg.req),  // Send size - must be >= 24
                  sizeof(send_msg.resp), // Receive limit - must be >= 68
                  hot_reply_port,        // Receive port
                  1000,                  // Timeout
                  MACH_PORT_NULL);       // Notification port
    printf("mach_msg returned %d '%s'\n", kr, mach_error_string(kr));
    printf("Send retcode post mach_msg: 0x%08x\n", ((mig_reply_error_t *)&send_msg.req)->RetCode);
    printf("Send bits post mach_msg: 0x%08x\n", send_msg.req.head.msgh_bits);
    printf("Send Length post mach_msg: %u\n", send_msg.req.head.msgh_size);
    printf("send_msg.ver_major %u ver_minor: %u\n", send_msg.resp.ver_major,
           send_msg.resp.ver_minor);
    printf("send_msg.login %u\n", send_msg.resp.login & 0xff);
    printf("resp: sz: %u\n", send_msg.resp.head.msgh_size);
    hexdump(&send_msg.resp, sizeof(send_msg.resp));
    assert(sizeof(send_msg.resp) % sizeof(uint32_t) == 0);
    hexdump32((uint32_t *)&send_msg.resp, sizeof(send_msg.resp) / sizeof(uint32_t));
    printf("hexdump32 just %u instead of %zu\n", send_msg.resp.head.msgh_size,
           sizeof(send_msg.resp));
    assert(send_msg.resp.head.msgh_size % sizeof(uint32_t) == 0);
    hexdump32((uint32_t *)&send_msg.resp, send_msg.resp.head.msgh_size / sizeof(uint32_t));
    dump_msg_body(&send_msg.resp.msgh_body);
    dump_msg_port_desc(&send_msg.resp.session_port);
    dump_msg_audit_trailer(&send_msg.resp.trailer);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to send phase A message: %s\n", mach_error_string(kr));
        return 1;
    }

    printf("Message sent successfully.\n");

    return 0;
}
