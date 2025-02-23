#pragma once

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stddef.h>
#include <stdint.h>

struct aspi_commpage_timeofday_data {
    uint64_t TimeStamp_tick;
    uint64_t TimeStamp_sec;
    uint64_t TimeStamp_frac;
    uint64_t Ticks_scale;
    uint64_t Ticks_per_sec;
};

#ifdef __arm64__

#define ASPI_COMM_PAGE_START_ADDRESS         0x0000000FFFFFC000ull
#define ASPI_COMM_PAGE_APPROX_TIME           (ASPI_COMM_PAGE_START_ADDRESS + 0x0C0ull)
#define ASPI_COMM_PAGE_APPROX_TIME_SUPPORTED (ASPI_COMM_PAGE_START_ADDRESS + 0x0C8ull)
#define ASPI_COMM_PAGE_NEWTIMEOFDAY_DATA     (ASPI_COMM_PAGE_START_ADDRESS + 0x120ull)
#define ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_TICKS                        \
    (ASPI_COMM_PAGE_NEWTIMEOFDAY_DATA +                             \
     offsetof(struct aspi_commpage_timeofday_data, TimeStamp_tick))
#define ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_SECONDS                     \
    (ASPI_COMM_PAGE_NEWTIMEOFDAY_DATA +                            \
     offsetof(struct aspi_commpage_timeofday_data, TimeStamp_sec))
#define ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_FRACS                        \
    (ASPI_COMM_PAGE_NEWTIMEOFDAY_DATA +                             \
     offsetof(struct aspi_commpage_timeofday_data, TimeStamp_frac))
#define ASPI_COMM_PAGE_NEWTIMEOFDAY_TICKS_SCALE \
    (ASPI_COMM_PAGE_NEWTIMEOFDAY_DATA + offsetof(struct aspi_commpage_timeofday_data, Ticks_scale))
#define ASPI_COMM_PAGE_NEWTIMEOFDAY_TICKS_PER_SEC                  \
    (ASPI_COMM_PAGE_NEWTIMEOFDAY_DATA +                            \
     offsetof(struct aspi_commpage_timeofday_data, Ticks_per_sec))

#define ASPI_COMM_PAGE_APPROX_TIME_VAL           (*(volatile uint64_t *)ASPI_COMM_PAGE_APPROX_TIME)
#define ASPI_COMM_PAGE_APPROX_TIME_SUPPORTED_VAL (*(uint8_t *)ASPI_COMM_PAGE_APPROX_TIME_SUPPORTED)
#define ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_TICKS_VAL                 \
    (*(volatile uint64_t *)ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_TICKS)
#define ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_SECONDS_VAL                 \
    (*(volatile uint64_t *)ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_SECONDS)
#define ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_FRACS_VAL                 \
    (*(volatile uint64_t *)ASPI_COMM_PAGE_NEWTIMEOFDAY_TS_FRACS)
#define ASPI_COMM_PAGE_NEWTIMEOFDAY_TICKS_SCALE_VAL                 \
    (*(volatile uint64_t *)ASPI_COMM_PAGE_NEWTIMEOFDAY_TICKS_SCALE)
#define ASPI_COMM_PAGE_NEWTIMEOFDAY_TICKS_PER_SEC_VAL        \
    (*(uint64_t *)ASPI_COMM_PAGE_NEWTIMEOFDAY_TICKS_PER_SEC)

#else
#error unsupported arch
#endif

#ifdef __cplusplus
}
#endif // __cplusplus
