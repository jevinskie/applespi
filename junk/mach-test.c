#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    pid_t child_pid;
    int child_status;
    kern_return_t kr;
    struct rusage_info_v4 ru4_before_reap = {{0}};
    struct rusage_info_v4 ru4_after_reap  = {{0}};

    // Command to run with posix_spawn
    char *child_argv[] = {"/opt/homebrew/bin/stress-ng", // Path to executable
                          "--memcpy",
                          "1", // One memcpy worker
                          "--memcpy-ops",
                          "100", // Perform 100 operations
                          NULL};

    // Initialize spawn attributes
    posix_spawnattr_t spawn_attrs;
    posix_spawnattr_init(&spawn_attrs);

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
