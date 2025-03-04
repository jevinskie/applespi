#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>

#define plog(str, args...) printf("[%6d] " str "\n", getpid(), ##args)
#define HandleError(kr)                                                                  \
    if (kr != KERN_SUCCESS) {                                                            \
        printf("error: line %d in PID: %d, (%d) 0x%x, %s\n", __LINE__, getpid(), kr, kr, \
               mach_error_string(kr));                                                   \
        exit(1);                                                                         \
    }

struct favorite_animal_msg {
    mach_msg_header_t header;
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

    mach_port_t localPort      = create_port(); // 1
    msg.header.msgh_bits       = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE,
                                                    MACH_MSG_TYPE_MAKE_SEND_ONCE, // 2
                                                    0, MACH_MSGH_BITS_COMPLEX);
    msg.header.msgh_local_port = localPort; // 3

    msg.header.msgh_id           = 12345;
    msg.header.msgh_remote_port  = sendPort;
    msg.header.msgh_size         = sizeof(msg);
    msg.header.msgh_voucher_port = MACH_PORT_NULL;

    char questionStr[1024] = {};
    snprintf(questionStr, 1024, "Yo, what's your favorite animal? [Sent from %d]", getpid());
    msg.count = 1;

    msg.question.address    = questionStr;
    msg.question.type       = MACH_MSG_OOL_DESCRIPTOR;
    msg.question.size       = (mach_msg_size_t)strlen(questionStr);
    msg.question.copy       = MACH_MSG_PHYSICAL_COPY;
    msg.question.deallocate = 0;

    plog("Sending message from child");
    HandleError(mach_msg(&msg.header,
                         MACH_RCV_MSG | MACH_SEND_MSG, // 4
                         sizeof(struct favorite_animal_msg),
                         sizeof(struct favorite_animal_msg) + MAX_TRAILER_SIZE, localPort, 0000000,
                         MACH_PORT_NULL));

    plog("!!!! Resp is \"%s\" !!!!!!", (char *)msg.question.address); // 5
}

void recv_message(mach_port_t localPort) {
    struct favorite_animal_msg msg = {};
    msg.header.msgh_local_port     = localPort;
    msg.header.msgh_size           = sizeof(msg) + MAX_TRAILER_SIZE;
    HandleError(mach_msg_receive(&msg.header));
    plog("msgh_id: %d", msg.header.msgh_id);
    plog("%s", (char *)msg.question.address);

    char respStr[1024];
    snprintf(respStr, 1024, "Koaka [Sent from %d]", getpid());
    msg.question.address = respStr;
    msg.question.size    = (mach_msg_size_t)strlen(respStr);
    msg.question.copy    = MACH_MSG_PHYSICAL_COPY;

    msg.header.msgh_local_port = MACH_PORT_NULL;
    HandleError(mach_msg_send(&msg.header));
}

int main() {
    mach_port_t port = create_port();
    pid_t pid        = fork();
    if (pid == 0) {
        plog("I am the child");
        sleep(2);
        send_message(port);
    } else if (pid > 0) {
        plog("I am the parent");
        sleep(2);

        recv_message(port);
        wait(&pid);
    }

    return 0;
}
