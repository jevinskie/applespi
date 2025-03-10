#include <CoreFoundation/CoreFoundation.h>
#include <uuid/uuid.h>
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

#include "applespi/apfs_spi.h"

int main(int argc, const char **argv) {
    if (argc != 3) {
        printf("usage: applespi-firmlinks-util <disk> <volume group uuid>\n");
        return 1;
    }
    uuid_t volume_group_id;
    uuid_parse(argv[1], volume_group_id);
    CFMutableArrayRef firmlinks = NULL;
    const OSStatus getfl_res =
        APFSContainerVolumeGroupGetFirmlinks(argv[1], volume_group_id, &firmlinks);
    printf("getfl_res: %d\n", getfl_res);
    printf("firmlinks: %p\n", firmlinks);
    if (firmlinks) {
        printf("len(firmlinks): %zi\n", CFArrayGetCount(firmlinks));
    }
    return 0;
}
