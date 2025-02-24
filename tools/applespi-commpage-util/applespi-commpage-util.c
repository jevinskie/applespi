#include <sys/signal.h>
#undef NDEBUG
#include <assert.h>

#include <crt_externs.h>
#include <inttypes.h>
#include <libproc.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#include <applespi/commpage_spi.h>

extern char **environ;

static void be_busy(void) {
    for (int i = 0; i < 10000; ++i) {
        usleep(1);
    }
}

void dump_rusage(void) {
    struct rusage_info_v4 ru;
    proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t *)&ru);
    printf("instructions: %" PRIu64 "\n", ru.ri_instructions);
    printf("cycles: %" PRIu64 "\n", ru.ri_cycles);
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

    dump_rusage();
#if 0
    dump_commpage_time_info();
    sleep(1);
    dump_rusage();
    for (size_t i = 0; i < (1ull << 24); ++i) {
        ASPI_COMM_PAGE_APPROX_TIME_VAL;
    }
    dump_rusage();
    dump_commpage_time_info();
    dump_rusage();
#endif

    struct rusage ru;
    struct rusage_info_v4 ru4   = {{0}};
    struct rusage_info_v4 ru4c  = {{0}};
    struct rusage_info_v4 ru4c2 = {{0}};
    pid_t child_pid;
    int child_status;
    char *child_argv[] = {
        "/opt/homebrew/bin/stress-ng", "--memcpy", "1", "--memcpy-ops", "1000", NULL};
    posix_spawn_file_actions_t fat;
    posix_spawn_file_actions_init(&fat);
    posix_spawnattr_t spawn_attrs;
    int psair = posix_spawnattr_init(&spawn_attrs);
    printf("psair: %d\n", psair);
    // int pssar = posix_spawnattr_setflags(&spawn_attrs, POSIX_SPAWN_START_SUSPENDED);
    // printf("pssar: %d\n", pssar);
    const int pres = posix_spawn(&child_pid, child_argv[0], NULL, &spawn_attrs, child_argv, NULL);
    posix_spawnattr_destroy(&spawn_attrs);
    // printf("child_pid: %d\n", child_pid);
    int prr1 = proc_pid_rusage(child_pid, RUSAGE_INFO_V4, (rusage_info_t *)&ru4);
    // printf("prr1: %x\n", prr1);
    // printf("sleep(1) begin\n");
    // fflush(stdout);
    // sleep(1);
    // printf("sleep(1) end\n");
    // fflush(stdout);
    // kill(child_pid, SIGCONT);
    usleep(1000);
    int prr3 = proc_pid_rusage(child_pid, RUSAGE_INFO_V4, (rusage_info_t *)&ru4c2);
    // while (waitpid(child_pid, &child_status, 0) != child_pid) {}
    int wr   = wait4(child_pid, &child_status, 0, &ru);
    int prr2 = proc_pid_rusage(child_pid, RUSAGE_INFO_V4, (rusage_info_t *)&ru4c);

    printf("pres: %d\n", pres);
    printf("child status raw: %d\n", child_status);
    printf("child status: %d\n", WEXITSTATUS(child_status));
    printf("child signaled: %d\n", WIFSIGNALED(child_status));
    printf("wr: %d\n", wr);
    printf("prr2: %d\n", prr2);
    printf("prr3: %d\n", prr3);
    fflush(stdout);

    printf("child instructions: %" PRIu64 "\n", ru4.ri_instructions);
    printf("child cycles: %" PRIu64 "\n", ru4.ri_cycles);

    printf("child copy instructions: %" PRIu64 "\n", ru4c.ri_instructions);
    printf("child copy cycles: %" PRIu64 "\n", ru4c.ri_cycles);

    printf("child copy post-kill instructions: %" PRIu64 "\n", ru4c2.ri_instructions);
    printf("child copy post-kill cycles: %" PRIu64 "\n", ru4c2.ri_cycles);

    // be_busy();
    return 0;
}
