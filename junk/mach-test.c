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

int main(void) {
    pid_t child_pid;
    int child_status;
    kern_return_t kr;
    kern_return_t tir;
    int aspr;
    mach_msg_type_number_t audit_token_size;
    struct rusage_info_v4 ru4_before_reap = {{0}};
    struct rusage_info_v4 ru4_after_reap  = {{0}};

    // Initialize spawn attributes
    posix_spawnattr_t spawn_attrs;
    posix_spawnattr_init(&spawn_attrs);

    // Command to run with posix_spawn
    char *child_argv[] = {"/Users/jevin/code/apple/utils/applespi/ret", NULL};

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

    const int saspr = posix_spawnattr_setauditsessionport_np(&spawn_attrs, audit_port_orig);
    if (saspr) {
        perror("posix_spawnattr_setauditsessionport_np");
    }

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

    // Start the process in suspended state so we can set up monitoring
    posix_spawnattr_setflags(&spawn_attrs, POSIX_SPAWN_START_SUSPENDED);

    // Spawn the child process
    int spawn_result = posix_spawn(&child_pid, child_argv[0], NULL, &spawn_attrs, child_argv, NULL);
    posix_spawnattr_destroy(&spawn_attrs);

    if (spawn_result != 0) {
        fprintf(stderr, "posix_spawn failed: %s\n", strerror(spawn_result));
        return EXIT_FAILURE;
    }

    printf("Child process spawned with PID %d\n", child_pid);

    // Get task port for the child
    mach_port_t task_port = MACH_PORT_NULL;
    kr                    = task_name_for_pid(mach_task_self(), child_pid, &task_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to get task port for PID %d: %s\n", child_pid,
                mach_error_string(kr));
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }

    // Create a notification port
    mach_port_t notification_port = MACH_PORT_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notification_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate notification port: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), task_port);
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }

    // Request notification when the task port becomes a dead name
    mach_port_t previous;
    kr = mach_port_request_notification(mach_task_self(), task_port, MACH_NOTIFY_DEAD_NAME, 0,
                                        notification_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to request notification: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), task_port);
        mach_port_deallocate(mach_task_self(), notification_port);
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }

    audit_token_t child_token;
    audit_token_size = TASK_AUDIT_TOKEN_COUNT;
    const kern_return_t tir2 =
        task_info(task_port, TASK_AUDIT_TOKEN, (integer_t *)&child_token, &audit_token_size);
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

    // Now allow the child to continue
    printf("Resuming child process...\n");
    kill(child_pid, SIGCONT);

    printf("Waiting for child process (PID %d) to exit...\n", child_pid);

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
        mach_port_deallocate(mach_task_self(), task_port);
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
    mach_port_deallocate(mach_task_self(), task_port);
    mach_port_deallocate(mach_task_self(), notification_port);

    return EXIT_SUCCESS;
}
