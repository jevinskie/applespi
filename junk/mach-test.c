#undef NDEBUG
#include <assert.h>

#include <bsm/audit.h>
#include <errno.h>
#include <libproc.h>
#include <mach/arm/kern_return.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/port.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

void token_thingy(mach_port_t port) {
    struct msg_s {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t port;
        mach_msg_audit_trailer_t trailer;
    };
    struct msg_s msg          = {};
    mach_msg_size_t recv_size = sizeof(msg.trailer);
    mach_msg_option_t options = MACH_SEND_MSG | MACH_RCV_MSG |
                                MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                                MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
    // mach_msg_option_t options = MACH_RCV_MSG | MACH_RCV_TRAILER_AUDIT;
    // msg.header.msgh_size         = sizeof(msg.header);
    // msg.header.msgh_remote_port  = port;
    // msg.header.msgh_local_port   = mach_task_self();
    // msg.header.msgh_voucher_port = MACH_PORT_NULL;

    printf("token_thiny port: %u 0x%08x\n", port, port);

    kern_return_t kr =
        mach_msg_overwrite(&msg.header, options, sizeof(msg), recv_size, mach_task_self(),
                           MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL, NULL, 0);
    if (kr != KERN_SUCCESS) {
        printf("mach_msg receive failed: 0x%08xu a.k.a '%s'\n", kr, mach_error_string(kr));
        abort();
    }

    mach_msg_audit_trailer_t *trailer =
        (mach_msg_audit_trailer_t *)((uint8_t *)&msg + msg.header.msgh_size);
    if (trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0) {
        printf("bad trailer type got %u instead of %u\n", trailer->msgh_trailer_type,
               MACH_MSG_TRAILER_FORMAT_0);
        abort();
    }
    if (trailer->msgh_trailer_size >= sizeof(mach_msg_audit_trailer_t)) {
        printf("bad trailer size got %u instead of %zu\n", trailer->msgh_trailer_size,
               sizeof(mach_msg_audit_trailer_t));
        abort();
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: mach-test <child executable to spawn> <child args>");
    }
    pid_t child_pid;
    int child_status;
    kern_return_t kr;
#if DO_AUDIT
    kern_return_t tir;
    int aspr;
    mach_msg_type_number_t audit_token_size;
#endif
    struct rusage_info_v4 ru4_before_reap = {};

    // Initialize spawn attributes
    posix_spawnattr_t spawn_attrs;
    posix_spawnattr_init(&spawn_attrs);

#if DO_AUDIT
    audit_token_t self_token_orig;
    audit_token_size = TASK_AUDIT_TOKEN_COUNT;
    tir              = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (integer_t *)&self_token_orig,
                                 &audit_token_size);
    if (tir != KERN_SUCCESS) {
        printf("task_info returned %d\n", tir);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 8; ++i) {
        printf("self_token_orig[%d]: 0x%08x\n", i, self_token_orig.val[i]);
    }
    printf("self_pid: 0x%08x %u\n", (uint32_t)getpid(), (uint32_t)getpid());
    printf("\n");

    const uint32_t self_asid_orig = self_token_orig.val[6];
    printf("self_asid_orig: 0x%08x %u\n", self_asid_orig, self_asid_orig);
    mach_port_name_t self_ass_port_orig = audit_session_self();
    printf("self_ass_port_orig: 0x%08x %u\n", self_ass_port_orig, self_ass_port_orig);

    mach_port_name_t audit_port_orig = MACH_PORT_NULL;
    aspr                             = audit_session_port(self_asid_orig, &audit_port_orig);
    printf("aspr: %d audit_port_orig: 0x%08x %u\n", aspr, audit_port_orig, audit_port_orig);
    assert(!aspr);

    auditinfo_addr_t auinfo_trigger_new_session = {
        .ai_termid =
            {
                .at_type = AU_IPv4,
            },
        .ai_auid = AU_DEFAUDITID,
        .ai_asid = AU_ASSIGN_ASID,
    };
    if (setaudit_addr(&auinfo_trigger_new_session, sizeof(auinfo_trigger_new_session))) {
        perror("setaudit_addr");
    }
    au_asid_t new_asid = AU_ASSIGN_ASID;
    printf("new_asid init: 0x%08x\n", new_asid);
    // const int saspr = posix_spawnattr_setauditsessionport_np(&spawn_attrs, self_asid_orig);
    // if (saspr) {
    //     perror("posix_spawnattr_setauditsessionport_np");
    // }
    // printf("new_asid fini: 0x%08x\n", new_asid);

    audit_token_t self_token_during;
    audit_token_size = TASK_AUDIT_TOKEN_COUNT;
    tir = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (integer_t *)&self_token_during,
                    &audit_token_size);
    if (tir != KERN_SUCCESS) {
        printf("task_info returned %d\n", tir);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 8; ++i) {
        printf("self_token_during[%d]: 0x%08x\n", i, self_token_during.val[i]);
    }
    printf("\n");

    const uint32_t self_asid_during = self_token_during.val[6];
    printf("self_asid_during: 0x%08x %u\n", self_asid_during, self_asid_during);
    mach_port_name_t self_ass_port_during = audit_session_self();
    printf("self_ass_port_during: 0x%08x %u\n", self_ass_port_during, self_ass_port_during);

    mach_port_name_t audit_port_during = MACH_PORT_NULL;
    aspr                               = audit_session_port(self_asid_during, &audit_port_during);
    printf("aspr: %d audit_port_during: 0x%08x %u\n", aspr, audit_port_during, audit_port_during);
    assert(!aspr);

    audit_token_t self_token_after;
    audit_token_size = TASK_AUDIT_TOKEN_COUNT;
    tir              = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (integer_t *)&self_token_after,
                                 &audit_token_size);
    if (tir != KERN_SUCCESS) {
        printf("task_info returned %d\n", tir);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 8; ++i) {
        printf("self_token_after[%d]: 0x%08x\n", i, self_token_after.val[i]);
    }
    printf("\n");

    const uint32_t self_asid_after = self_token_after.val[6];
    printf("self_asid_after: 0x%08x %u\n", self_asid_after, self_asid_after);
    mach_port_name_t self_ass_port_after = audit_session_self();
    printf("self_ass_port_after: 0x%08x %u\n", self_ass_port_after, self_ass_port_after);

    mach_port_name_t audit_port_after = MACH_PORT_NULL;
    aspr                              = audit_session_port(self_asid_after, &audit_port_after);
    printf("aspr: %d audit_port_after: 0x%08x %u\n", aspr, audit_port_after, audit_port_after);
    assert(!aspr);
#endif

    // Start the process in suspended state so we can set up monitoring
    posix_spawnattr_setflags(&spawn_attrs, POSIX_SPAWN_START_SUSPENDED);

    // Spawn the child process
    int spawn_result = posix_spawn(&child_pid, argv[1], NULL, &spawn_attrs, &argv[1], NULL);
    posix_spawnattr_destroy(&spawn_attrs);

    if (spawn_result != 0) {
        fprintf(stderr, "posix_spawn failed: %s\n", strerror(spawn_result));
        return EXIT_FAILURE;
    }

    printf("Child process spawned with PID %d\n", child_pid);

    // Get task port for the child
    mach_port_t child_task_name_port = MACH_PORT_NULL;
    kr = task_name_for_pid(mach_task_self(), child_pid, &child_task_name_port);
    // kr = task_for_pid(mach_task_self(), child_pid, &child_task_name_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to get task port for PID %d: %s\n", child_pid,
                mach_error_string(kr));
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }
    printf("child_task_name_port: %u 0x%08x\n", child_task_name_port, child_task_name_port);

    // Create a notification port
    mach_port_t notification_port = MACH_PORT_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notification_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate notification port: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), child_task_name_port);
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }
    printf("notification_port: %u 0x%08x\n", notification_port, notification_port);

    // Request notification when the task port becomes a dead name
    mach_port_t prev_notif_port = MACH_PORT_NULL;
    kr = mach_port_request_notification(mach_task_self(), child_task_name_port,
                                        MACH_NOTIFY_DEAD_NAME, 0, notification_port,
                                        MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev_notif_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to request notification: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), child_task_name_port);
        mach_port_deallocate(mach_task_self(), notification_port);
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }
    printf("prev_notif_port: %u 0x%08x\n", prev_notif_port, prev_notif_port);
    printf("notification_port: %u 0x%08x\n", notification_port, notification_port);

#if DO_AUDIT
    audit_token_t child_token_susp;
    audit_token_size = TASK_AUDIT_TOKEN_COUNT;
    tir = task_info(child_task_name_port, TASK_AUDIT_TOKEN, (integer_t *)&child_token_susp,
                    &audit_token_size);
    if (tir != KERN_SUCCESS) {
        printf("task_info on child returned %d\n", tir);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 8; ++i) {
        printf("child_token_susp[%d]: 0x%08x\n", i, child_token_susp.val[i]);
    }
    printf("\n");

    audit_token_t child_token;
    audit_token_size         = TASK_AUDIT_TOKEN_COUNT;
    const kern_return_t tir2 = task_info(child_task_name_port, TASK_AUDIT_TOKEN,
                                         (integer_t *)&child_token, &audit_token_size);
    if (tir2 != KERN_SUCCESS) {
        printf("task_info 2 returned %d\n", tir2);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 8; ++i) {
        printf("child_token[%d]: 0x%08x\n", i, child_token.val[i]);
    }
    printf("child_pid: 0x%08x %u\n", (uint32_t)child_pid, (uint32_t)child_pid);

    const uint32_t child_asid = child_token.val[6];
    printf("child_asid: 0x%08x %u\n", child_asid, child_asid);
#endif

    // Now allow the child to continue
    printf("Resuming child process...\n");
    kill(child_pid, SIGCONT);

    printf("Waiting for child process (PID %d) to exit...\n", child_pid);

    usleep(1000);

    token_thingy(mach_task_self());
    // token_thingy(child_task_name_port);

    // Prepare to receive the dead-name notification
    struct {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t port;
        mach_msg_trailer_t trailer;
    } message;

    // Wait for the message (this will block until the process exits)
    kr = mach_msg(&message.header, MACH_RCV_MSG, 0, sizeof(message), notification_port,
                  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to receive message: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), child_task_name_port);
        mach_port_deallocate(mach_task_self(), notification_port);
        return EXIT_FAILURE;
    }

    printf("Child process (PID %d) has exited. Notification received.\n", child_pid);

    // Get resource usage before reaping
    printf("Getting resource usage before reaping...\n");
    if (proc_pid_rusage(child_pid, RUSAGE_INFO_V4, (rusage_info_t *)&ru4_before_reap) != 0) {
        perror("proc_pid_rusage before reaping failed");
    } else {
        printf("Successfully collected resource usage before reaping\n");
    }

    // Now reap the child process
    printf("Reaping child process...\n");
    if (waitpid(child_pid, &child_status, 0) == -1) {
        perror("waitpid failed");
    } else {
        printf("Child process reaped successfully\n");
        if (WIFEXITED(child_status)) {
            printf("Child exited with status: %d\n", WEXITSTATUS(child_status));
        } else if (WIFSIGNALED(child_status)) {
            printf("Child terminated by signal: %d\n", WTERMSIG(child_status));
        }
    }

    // Print resource usage information
    printf("\nResource Usage Report:\n");
    printf("Physical footprint: %llu bytes\n", ru4_before_reap.ri_phys_footprint);
    printf("CPU user time: %llu ns\n", ru4_before_reap.ri_user_time);
    printf("CPU system time: %llu ns\n", ru4_before_reap.ri_system_time);
    printf("Threads: %llu instructions\n", ru4_before_reap.ri_instructions);
    printf("Threads: %llu cycles\n", ru4_before_reap.ri_cycles);
    printf("Wakeups: %llu\n",
           ru4_before_reap.ri_pkg_idle_wkups + ru4_before_reap.ri_interrupt_wkups);

    // Clean up Mach ports
    mach_port_deallocate(mach_task_self(), child_task_name_port);
    mach_port_deallocate(mach_task_self(), notification_port);

    return EXIT_SUCCESS;
}
