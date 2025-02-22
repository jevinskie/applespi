#include <inttypes.h>
#include <mach/kern_return.h>
#include <mach/mach_time.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    printf("applespi-time-info utility\n");
    mach_timebase_info_data_t tb_info;
    kern_return_t kr = mach_timebase_info(&tb_info);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "mach_timebase_info failed, return value is 0x%08" PRIx32 "\n", kr);
        return 1;
    }
    printf("tb_info.numer: %" PRIu32 "\n", tb_info.numer);
    printf("tb_info.denom: %" PRIu32 "\n", tb_info.denom);
    return 0;
}
