#undef NDEBUG
#include <assert.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <unistd.h>

#define NUM_X                    10000
#define BUF_SZ                   (16 * 1024)
#define DUMP_SZ                  (16 * 1024)

#define _COMM_PAGE_START_ADDRESS 0x0000000FFFFFC000ULL

static void be_busy(void) {
    int dev_null_fd = open("/dev/null", O_RDONLY);
    assert(dev_null_fd >= 0);
    for (int i = 0; i < NUM_X; ++i) {
        char junk[BUF_SZ];
        write(dev_null_fd, junk, sizeof(junk));
    }
    for (int i = 0; i < NUM_X; ++i) {
        usleep(1);
    }
}

static void dump_commpage(const char *path, size_t sz) {
    void *buf = malloc(sz);
    assert(buf);
    memcpy(buf, (void *)(uintptr_t)_COMM_PAGE_START_ADDRESS, sz);
    FILE *f = fopen(path, "wb");
    assert(f);
    assert(1 == fwrite(buf, sz, 1, f));
    assert(!fclose(f));
    free(buf);
}

int main(void) {
    printf("applespi-commpage-dump begin\n");
    dump_commpage("commpage_dump_start.bin", DUMP_SZ);
    be_busy();
    dump_commpage("commpage_dump_end.bin", DUMP_SZ);
    printf("applespi-commpage-dump done\n");
    printf("applespi-commpage-dump size probe beginning\n");
    for (size_t i = 1; i < 128; ++i) {
        printf("dumping mul: %zu sz: %zu\n", i, i * 1024);
        fflush(stdout);
        dump_commpage("commpage_dump_size_probe.bin", i * 1024);
        printf("dumping mul: %zu sz: %zu - SUCCESS\n", i, i * 1024);
        fflush(stdout);
    }
    return 0;
}
