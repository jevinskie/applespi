#include <CoreFoundation/CFBase.h>
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
    printf("getfl_res: %d\n", getfl_res);
    printf("firmlinks: %p\n", firmlinks);
    if (firmlinks) {
        const CFIndex numfl = CFArrayGetCount(firmlinks);
        printf("len(firmlinks): %zi\n", numfl);
        for (CFIndex i = 0; i < numfl; ++i) {
            CFStringRef val      = CFArrayGetValueAtIndex(firmlinks, i);
            CFTypeID tid         = CFGetTypeID(val);
            CFStringRef tid_desc = CFCopyTypeIDDescription(tid);
            char desc[1024];
            assert(CFStringGetCString(tid_desc, desc, sizeof(desc), kCFStringEncodingUTF8));
            const char *tid_cstr = CFStringGetCStringPtr(tid_desc, kCFStringEncodingUTF8);
            // printf("fl[%zi] = %p tid: 0x%zx tid_desc: %p %s\n", i, val, tid, tid_desc, desc);
            assert(CFStringGetCString(val, desc, sizeof(desc), kCFStringEncodingUTF8));
            printf("fl[%zi] = '%s'\n", i, desc);
        }
    }
    return 0;
}
