#undef NDEBUG
#include <assert.h>

#include <CoreFoundation/CoreFoundation.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "applespi/apfs_spi.h"

int main(int argc, const char **argv) {
    if (argc != 3) {
        printf("usage: applespi-firmlinks-util <disk> <volume group uuid>\n");
        return 1;
    }
    uuid_t volume_group_id;
    uuid_parse(argv[2], volume_group_id);
    CFMutableArrayRef firmlinks = NULL;
    const OSStatus getfl_res =
        APFSContainerVolumeGroupGetFirmlinks(argv[1], volume_group_id, &firmlinks);
    printf("APFSContainerVolumeGroupGetFirmlinks result: %d\n", getfl_res);
    if (firmlinks) {
        const CFIndex numfl = CFArrayGetCount(firmlinks);
        printf("len(firmlinks): %zi\n", numfl);
        for (CFIndex i = 0; i < numfl; ++i) {
            CFStringRef val = CFArrayGetValueAtIndex(firmlinks, i);
            assert(val);
            char path[1024];
            assert(CFStringGetCString(val, path, sizeof(path), kCFStringEncodingUTF8));
            printf("firmlink_entry[%zi] = '%s'\n", i, path);
        }
        CFRelease(firmlinks);
    }
    return 0;
}
