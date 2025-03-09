#include <os/log.h>
#include <unistd.h>

int main(int argc, const char **argv) {
    (void)argv;
    os_log_t logger;
    int do_oslog = argc != 1;
    pid_t my_pid = getpid();
    printf("i'm spin-sleep at pid %d\n", my_pid);
    if (do_oslog) {
        logger = os_log_create("vin.je.spin-sleep", "spin-sleep-cat");
        os_log(logger, "spin-sleep before spin pid: %{public}d", my_pid);
    }
    size_t i = 0;
    while (1) {
        if (do_oslog) {
            os_log(logger, "spin-sleep second: %{public}zu", i++);
        }
        sleep(1);
    }
    return 0;
}
