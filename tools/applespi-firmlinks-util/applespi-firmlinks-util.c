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
#include <sys/mount.h>
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
    if (!(argc == 1 || argc == 2 || argc == 3)) {
        printf("usage: applespi-firmlinks-util <disk> <volume group uuid | optional>\n");
        return 1;
    }
    uuid_t volume_group_id;
    if (argc == 3) {
        assert(!uuid_parse(argv[2], volume_group_id));
    }
    char dev_buf[PATH_MAX];
    if (argc == 1 || argc == 2) {
        char uuid_str[UUID_BUF_LEN_W_NUL] = {0};
        get_kern_bootuuid(uuid_str);
        printf("kern.bootuuid: %s\n", uuid_str);
        assert(!uuid_parse(uuid_str, volume_group_id));
        if (argc == 2) {
            strncpy(dev_buf, argv[1], sizeof(dev_buf) - 1);
        }
    }
    if (argc == 1) {

        dev_buf[0]            = '\0';
        struct statfs *mounts = NULL;
        int num_mounts        = getmntinfo_r_np(&mounts, 0);
        assert(num_mounts > 0);
        assert(mounts);
        for (int i = 0; i < num_mounts; ++i) {
            if (memcmp(mounts[i].f_mntonname, "/", sizeof("/"))) {
                continue;
            }
            const char *const dev_path = mounts[i].f_mntfromname;
            assert(!memcmp(dev_path, "/dev/disk", sizeof("/dev/disk") - 1));
            const char *const dev_name        = dev_path + (sizeof("/dev/") - 1);
            const size_t dev_name_len         = strlen(dev_name);
            const char *const dev_trailer     = dev_name + (sizeof("disk") - 1);
            const size_t dev_trailer_len      = strlen(dev_trailer);
            const char *const dev_trailer_nul = dev_trailer + dev_trailer_len;
            assert(dev_trailer_len > 0);
            size_t num_s        = 0;
            const char *first_s = NULL;
            for (size_t j = 0; j < dev_trailer_len; ++j) {
                const char c = dev_trailer[j];
                if (c == 's') {
                    if (!num_s) {
                        first_s = &dev_trailer[j];
                    }
                    ++num_s;
                } else {
                    assert(c >= '0' && c <= '9');
                }
            }
            assert(num_s <= 2);
            if (num_s == 2) {
                assert(dev_trailer_len >= 4); // sXsY
                assert(first_s[1] != 's');
                assert(dev_trailer[dev_trailer_len - 1] != 's');
            } else if (num_s == 1) {
                assert(dev_trailer_len >= 2); // sX
                assert(first_s < dev_trailer_nul);
            }
            if (num_s >= 1) {
                assert(first_s);
                const size_t dev_len = (sizeof("disk") - 1) + (dev_trailer_len - strlen(first_s));
                assert(dev_len + 1 < sizeof(dev_buf));
                memcpy(dev_buf, dev_name, dev_len);
                dev_buf[dev_len] = '\0';
            } else {
                assert(dev_name_len + 1 < sizeof(dev_buf));
                memcpy(dev_buf, dev_name, dev_name_len + 1);
            }
            break;
        }
        free(mounts);
        assert(dev_buf[0] != '\0');
    }
    printf("disk: %s\n", dev_buf);
    CFMutableArrayRef firmlinks = NULL;
    const OSStatus getfl_res =
        APFSContainerVolumeGroupGetFirmlinks(dev_buf, volume_group_id, &firmlinks);
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
