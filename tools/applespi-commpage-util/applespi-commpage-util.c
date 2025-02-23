#undef NDEBUG
#include <assert.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <applespi/commpage_spi.h>

static void be_busy(void) {
    for (int i = 0; i < 10000; ++i) {
        usleep(1);
    }
}

static void dump_commpage_time_info(void) {
    const uint8_t approx_time_supported = ASPI_COMM_PAGE_APPROX_TIME_SUPPORTED_VAL;
    const uint64_t approx_time_val =
        approx_time_supported ? ASPI_COMM_PAGE_APPROX_TIME_VAL : 0xDEADBEEFull;
    const uint64_t TimeStamp_tick = ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_TICKS_VAL;
    const uint64_t TimeStamp_sec  = ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_SECONDS_VAL;
    const uint64_t TimeStamp_frac = ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_FRACS_VAL;
    const uint64_t Ticks_scale    = ASPI_COMM_PAGE_NEWTIMEOFDAY_TICKS_SCALE_VAL;
    const uint64_t Ticks_per_sec  = ASPI_COMM_PAGE_NEWTIMEOFDAY_TICKS_PER_SEC_VAL;
    printf("approx_time_supported: %" PRIu8 "\n", approx_time_supported);
    printf("approx_time_val: %" PRIu64 "\n", approx_time_val);
    printf("TimeStamp_tick: %" PRIu64 "\n", TimeStamp_tick);
    printf("TimeStamp_sec: %" PRIu64 "\n", TimeStamp_sec);
    printf("TimeStamp_frac: %" PRIu64 "\n", TimeStamp_frac);
    printf("Ticks_scale: %" PRIu64 "\n", Ticks_scale);
    printf("Ticks_per_sec: %" PRIu64 "\n", Ticks_per_sec);
}

int main(void) {
    printf("applespi-commpage-util\n");
    dump_commpage_time_info();
    sleep(1);
    dump_commpage_time_info();
    // be_busy();
    return 0;
}
