#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

void monitor_task_port(mach_port_t task_port, pid_t child_pid) {
    mach_port_t notify_port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify_port);
    mach_port_insert_right(mach_task_self(), notify_port, notify_port, MACH_MSG_TYPE_MAKE_SEND);

    // Request notification when the task port dies
    mach_port_request_notification(mach_task_self(), task_port, MACH_NOTIFY_DEAD_NAME, 0,
                                   notify_port, MACH_MSG_TYPE_MAKE_SEND, MACH_PORT_NULL);

    struct {
        mach_msg_header_t header;
        mach_msg_trailer_t trailer;
    } message;

    // Wait for the dead-name notification
    mach_msg(&message.header, MACH_RCV_MSG, 0, sizeof(message), notify_port, MACH_MSG_TIMEOUT_NONE,
             MACH_PORT_NULL);

    printf("Child process (PID %d) exited, task port is now dead.\n", child_pid);

    // Get resource usage *before* reaping the process
    struct rusage usage;
    getrusage(RUSAGE_CHILDREN, &usage);
    printf("User CPU time: %ld.%06d sec, System CPU time: %ld.%06d sec\n", usage.ru_utime.tv_sec,
           usage.ru_utime.tv_usec, usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);

    // Reap process
    waitpid(child_pid, NULL, 0);
    printf("Child process (PID %d) reaped.\n", child_pid);
}

int main() {
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        sleep(2);
        return 0;
    }

    // Parent process
    sleep(1); // Ensure child is alive before grabbing task port

    mach_port_t task_port;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid() failed: %d\n", kr);
        return 1;
    }

    monitor_task_port(task_port, pid);
    return 0;
}
