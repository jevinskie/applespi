int main(void) {
    sigset_t mask;
    siginfo_t info;
    struct rusage_info_v4 ru4_start = {{0}};
    struct rusage_info_v4 ru4_end   = {{0}};
    pid_t child_pid;
    int child_status;
    char *child_argv[] = {
        "/opt/homebrew/bin/stress-ng", "--memcpy", "1", "--memcpy-ops", "100", NULL};
    posix_spawnattr_t spawn_attrs;
    posix_spawnattr_init(&spawn_attrs);
    posix_spawnattr_setflags(&spawn_attrs, POSIX_SPAWN_START_SUSPENDED); // private API but OK

    // pass through to child
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

    // SIGCHLD configuration
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL); // Block SIGCHLD so we can wait on it explicitly

    // spawn, check rusage, wait on SIGCHLD, call wait to reap child, check rusage
    posix_spawn(&child_pid, child_argv[0], NULL, &spawn_attrs, child_argv, NULL);
    posix_spawnattr_destroy(&spawn_attrs);
    kill(child_pid, SIGCONT);
    sigsuspend(&mask);
    proc_pid_rusage(child_pid, RUSAGE_INFO_V4, (rusage_info_t *)&ru4_start);
    waitpid(child_pid, &child_status, 0);
    proc_pid_rusage(child_pid, RUSAGE_INFO_V4, (rusage_info_t *)&ru4_end);

    // TODO:
    // show ru4_end - ru4_start data deltas

    return 0;
}
