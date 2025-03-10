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
#include <sys/sysctl.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "applespi/apfs_spi.h"

#define UUID_BUF_LEN_W_NUL 37

void get_kern_bootuuid(char uuid_str_buf[UUID_BUF_LEN_W_NUL]) {
    assert(uuid_str_buf);
    size_t sz = UUID_BUF_LEN_W_NUL;
    assert(!sysctlbyname("kern.bootuuid", uuid_str_buf, &sz, NULL, 0));
}

int main(int argc, const char **argv) {
    if (!(argc == 2 || argc == 3)) {
        printf("usage: applespi-firmlinks-util <disk> <volume group uuid | optional>\n");
        return 1;
    }
    uuid_t volume_group_id;
    if (argc == 3) {
        assert(!uuid_parse(argv[2], volume_group_id));
    } else {
        char uuid_str[UUID_BUF_LEN_W_NUL] = {0};
        get_kern_bootuuid(uuid_str);
        printf("kern.bootuuid: %s\n", uuid_str);
        assert(!uuid_parse(uuid_str, volume_group_id));
    }
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
