#include <mach/message.h>
#undef NDEBUG
#include <assert.h>

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define plog(str, args...) printf("[%6d] " str "\n", getpid(), ##args)
#define HandleError(kr)                                                                  \
    if (kr != KERN_SUCCESS) {                                                            \
        printf("error: line %d in PID: %d, (%d) 0x%x, %s\n", __LINE__, getpid(), kr, kr, \
               mach_error_string(kr));                                                   \
        exit(1);                                                                         \
    }

struct port_msg {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t port;
};

struct favorite_animal_msg {
    mach_msg_header_t head;
    mach_msg_size_t count;              // will be 1
    mach_msg_ool_descriptor_t question; // is type MACH_MSG_OOL_DESCRIPTOR
};

mach_port_t create_port(void) {
    mach_port_t port = MACH_PORT_NULL;
    // There's also mach_port_construct for a one liner but you will see more
    // examples of going this way
    HandleError(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port));
    HandleError(mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND));
    plog("port is 0x%x", port);

    return port;
}

void send_message(mach_port_t remotePort) {

    mach_port_t sendPort              = MACH_PORT_NULL;
    mach_msg_type_name_t acquiredType = 0;
    task_t parentTask                 = TASK_NULL;
    HandleError(task_for_pid(mach_task_self(), getppid(), &parentTask));
    HandleError(mach_port_extract_right(parentTask, remotePort, MACH_MSG_TYPE_MAKE_SEND_ONCE,
                                        &sendPort, &acquiredType));

    struct favorite_animal_msg msg = {};

    mach_port_t localPort    = create_port(); // 1
    msg.head.msgh_bits       = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE,
                                                  MACH_MSG_TYPE_MAKE_SEND_ONCE, // 2
                                                  0, MACH_MSGH_BITS_COMPLEX);
    msg.head.msgh_local_port = localPort; // 3

    msg.head.msgh_id           = 12345;
    msg.head.msgh_remote_port  = sendPort;
    msg.head.msgh_size         = sizeof(msg);
    msg.head.msgh_voucher_port = MACH_PORT_NULL;

    char questionStr[1024] = {};
    snprintf(questionStr, 1024, "Yo, what's your favorite animal? [Sent from %d]", getpid());
    msg.count = 1;

    msg.question.address    = questionStr;
    msg.question.type       = MACH_MSG_OOL_DESCRIPTOR;
    msg.question.size       = (mach_msg_size_t)strlen(questionStr);
    msg.question.copy       = MACH_MSG_PHYSICAL_COPY;
    msg.question.deallocate = 0;

    plog("Sending message from child");
    HandleError(mach_msg(&msg.head,
                         MACH_RCV_MSG | MACH_SEND_MSG, // 4
                         sizeof(struct favorite_animal_msg),
                         sizeof(struct favorite_animal_msg) + MAX_TRAILER_SIZE, localPort, 0000000,
                         MACH_PORT_NULL));

    plog("!!!! Resp is \"%s\" !!!!!!", (char *)msg.question.address); // 5
}

void recv_message(mach_port_t localPort) {
    struct favorite_animal_msg msg = {};
    msg.head.msgh_local_port       = localPort;
    msg.head.msgh_size             = sizeof(msg) + MAX_TRAILER_SIZE;
    HandleError(mach_msg_receive(&msg.head));
    plog("msgh_id: %d", msg.head.msgh_id);
    plog("%s", (char *)msg.question.address);

    char respStr[1024];
    snprintf(respStr, 1024, "Koaka [Sent from %d]", getpid());
    msg.question.address = respStr;
    msg.question.size    = (mach_msg_size_t)strlen(respStr);
    msg.question.copy    = MACH_MSG_PHYSICAL_COPY;

    msg.head.msgh_local_port = MACH_PORT_NULL;
    HandleError(mach_msg_send(&msg.head));
}

int main() {
    // mach_port_t port = create_port();
    int kr;
    mach_port_t fake_bsp = MACH_PORT_NULL;
    kr                   = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &fake_bsp);
    printf("pre MACH_PORT_VALID(fake_bsp): %d port: 0x%08x\n", MACH_PORT_VALID(fake_bsp), fake_bsp);
    if (kr != KERN_SUCCESS) {
        mach_error("mach_port_allocate", kr);
        abort();
    }
    kr = mach_port_insert_right(mach_task_self(), fake_bsp, fake_bsp, MACH_MSG_TYPE_MAKE_SEND);
    printf("pre post-mach_port_insert_right MACH_PORT_VALID(fake_bsp): %d port: 0x%08x\n",
           MACH_PORT_VALID(fake_bsp), fake_bsp);
    if (kr != KERN_SUCCESS) {
        mach_error("mach_port_insert_right", kr);
        abort();
    }
    kr = task_set_bootstrap_port(mach_task_self(), fake_bsp);
    if (kr != KERN_SUCCESS) {
        mach_error("task_set_bootstrap_port", kr);
        abort();
    }
    pid_t pid = fork();
    if (pid == 0) {
        plog("I am the child");
        sleep(1);
        kr = task_get_bootstrap_port(mach_task_self(), &fake_bsp);
        if (kr != KERN_SUCCESS) {
            mach_error("failed to get parent bootstrap port", kr);
            abort();
        }
        task_t child_self_task_kernel_port = MACH_PORT_NULL;
        kr =
            task_get_special_port(mach_task_self(), TASK_KERNEL_PORT, &child_self_task_kernel_port);
        printf("child MACH_PORT_VALID(child_self_task_kernel_port): %d port: 0x%08x\n",
               MACH_PORT_VALID(child_self_task_kernel_port), child_self_task_kernel_port);
        if (KERN_SUCCESS != kr) {
            mach_error("child task_get_special_port", kr);
            abort();
        }
        struct port_msg pmsg = {.head =
                                    {
                                        .msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) |
                                                     MACH_MSGH_BITS_COMPLEX,
                                        .msgh_size        = sizeof(struct port_msg),
                                        .msgh_remote_port = fake_bsp,
                                        .msgh_local_port  = MACH_PORT_NULL,
                                    },
                                .body =
                                    {
                                        .msgh_descriptor_count = 1,
                                    },
                                .port = {
                                    .name        = child_self_task_kernel_port,
                                    .disposition = MACH_MSG_TYPE_COPY_SEND,
                                    .type        = MACH_MSG_PORT_DESCRIPTOR,
                                }};
        printf("child calling mach_msg_send(&pmsg.head)\n");
        fflush(stdout);
        kr = mach_msg_send(&pmsg.head);
        printf("child MACH_PORT_VALID(fake_bsp): %d port: 0x%08x\n", MACH_PORT_VALID(fake_bsp),
               fake_bsp);
        printf("child MACH_PORT_VALID(child_self_task_kernel_port): %d port: 0x%08x\n",
               MACH_PORT_VALID(child_self_task_kernel_port), child_self_task_kernel_port);
        if (kr != KERN_SUCCESS) {
            mach_error("child mach_msg_send(&pmsg.header)", kr);
            abort();
        }
        // mach_port_deallocate(mach_task_self(), child_self_task_kernel_port);
        sleep(1);
        printf("child done sleeping one, sent its port, sleeping for 5 seconds\n");
        fflush(stdout);
        sleep(5);
        // send_message(port);
    } else if (pid > 0) {
        plog("I am the parent");
        printf("parent MACH_PORT_VALID(bootstrap_port): %d port: 0x%08x\n",
               MACH_PORT_VALID(bootstrap_port), bootstrap_port);
        kr = task_set_bootstrap_port(mach_task_self(), bootstrap_port);
        if (kr != KERN_SUCCESS) {
            mach_error("post fork parent task_set_bootstrap_port", kr);
            abort();
        }
        sleep(3);
        struct {
            struct port_msg msg;
            mach_msg_trailer_t trailer;
        } parent_pmsg;
        memset(&parent_pmsg, 0, sizeof(parent_pmsg));

        kr = mach_msg(&parent_pmsg.msg.head, MACH_RCV_MSG, 0, sizeof(parent_pmsg), fake_bsp,
                      MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        printf("parent MACH_PORT_VALID(fake_bsp) post mach_msg: %d\n", MACH_PORT_VALID(fake_bsp));
        mach_port_t parents_child_port = parent_pmsg.msg.port.name;
        printf("parent MACH_PORT_VALID(parents_child_port): %d port: 0x%08x\n",
               MACH_PORT_VALID(parents_child_port), parents_child_port);
        if (kr != KERN_SUCCESS) {
            mach_error("post fork parent mach_msg get port", kr);
            abort();
        }
        assert(MACH_PORT_VALID(parents_child_port));
        // recv_message(port);
        wait(&pid);
    }

    return 0;
}
