#include <mach/mach_traps.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, const char **argv) {
    if (argc != 2) {
        return 1;
    }
    int n = atoi(argv[1]);
    for (int i = 0; i < n; ++i) {
        usleep(10000);
        swtch_pri(0);
    }
    return 0;
}
