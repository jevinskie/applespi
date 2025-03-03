#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>

// Function to receive messages from notifyd
void receive_notification(void) {
    // Get the bootstrap port
    mach_port_t bootstrap_port;
    task_get_bootstrap_port(mach_task_self(), &bootstrap_port);

    // Look up the notifyd service port
    // notifyd is a system service that's accessible even in sandboxed apps
    mach_port_t service_port;
    kern_return_t kr =
        bootstrap_look_up(bootstrap_port, "com.apple.system.notification_center", &service_port);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to look up notifyd service: %s\n", mach_error_string(kr));
        return;
    }

    printf("Successfully connected to notifyd service\n");

    // Set up receive port for responses
    mach_port_t receive_port;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &receive_port);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate receive port: %s\n", mach_error_string(kr));
        return;
    }

    // Create a port set to listen on
    mach_port_t port_set;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &port_set);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate port set: %s\n", mach_error_string(kr));
        return;
    }

    // Add our receive port to the port set
    kr = mach_port_insert_member(mach_task_self(), receive_port, port_set);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to insert port into port set: %s\n", mach_error_string(kr));
        return;
    }

    // Register for a specific notification
    // We're using the darwin.launchd.domain as an example that should be accessible
    // even in sandboxed apps
    const char *notification_name = "com.apple.system.clock_set";

    // Use the notifyd service to register for the notification
    // This is a simplified example - a real implementation would use the notify_register_mach_port
    // API from the notify.h header, but we're working directly with Mach for this example

    printf("Waiting for messages (press Ctrl+C to quit)...\n");

    // Message receiving loop
    while (1) {
        mach_msg_header_t header;

        // Receive a message with a timeout
        kr = mach_msg(&header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(header), port_set, 1000,
                      MACH_PORT_NULL);

        if (kr == MACH_RCV_TIMEOUT) {
            // No message received within timeout, just continue
            continue;
        } else if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Error receiving message: %s\n", mach_error_string(kr));
            break;
        }

        // We received a message
        printf("Received a Mach message from port %u\n", header.msgh_remote_port);

        // Deallocate the received message
        mach_msg_destroy(&header);
    }

    // Clean up
    mach_port_deallocate(mach_task_self(), service_port);
    mach_port_deallocate(mach_task_self(), receive_port);
    mach_port_deallocate(mach_task_self(), port_set);
}

int main(int argc, const char *argv[]) {
    printf("Starting Mach message receiver...\n");

    // Set up a run loop to process asynchronous events
    CFRunLoopSourceContext context = {0};
    CFRunLoopSourceRef source      = CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &context);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);

    // Start the message receiving function on a separate thread
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
                   ^{ receive_notification(); });

    // Run the main run loop
    printf("Running main loop...\n");
    CFRunLoopRun();

    return 0;
}
