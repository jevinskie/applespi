#undef NDEBUG
#include <assert.h>

#include <dlfcn.h>
#include <errno.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int task_read_for_pid(mach_port_t target_tport, int pid, mach_port_t *t);

extern char **environ;

static const char prog_path[] = "/usr/bin/lsmp";

int main(void) {
    char pid_str[]           = "XXXXXXXXXX";
    const char *const argv[] = {prog_path, "-v", "-p", pid_str, NULL};
    pid_t self_pid           = getpid();
    sprintf(pid_str, "%d", self_pid);
    for (size_t i = 0; i < sizeof(argv) / sizeof(*argv); ++i) {
        printf("argv[%zd] = '%s'\n", i, argv[i]);
    }
    puts("");

    void *h = dlopen(prog_path, RTLD_LOCAL);
    assert(h);
    void *s = dlsym(h, "exit");
    printf("s: %p\n", s);

    const task_t self_regular = mach_task_self();
    printf("self task regular: 0x%08x aka %d\n", self_regular, self_regular);

    task_t self_read                   = MACH_PORT_NULL;
    errno                              = 0;
    int task_read_for_pid_res          = task_read_for_pid(self_regular, self_pid, &self_read);
    const int ctask_read_for_pid_errno = errno;
    if (task_read_for_pid_res != KERN_SUCCESS) {
        fprintf(stderr, "task_read_for_pid() failed: ret: %d mach_error: '%s' errno: %d aka '%s'\n",
                task_read_for_pid_res, mach_error_string(task_read_for_pid_res),
                ctask_read_for_pid_errno, strerror(ctask_read_for_pid_errno));
        return 2;
    }
    printf("self task read:    0x%08x aka %d\n", self_read, self_read);

    task_t self_name                   = MACH_PORT_NULL;
    errno                              = 0;
    int task_name_for_pid_res          = task_name_for_pid(self_regular, self_pid, &self_name);
    const int ctask_name_for_pid_errno = errno;
    if (task_name_for_pid_res != KERN_SUCCESS) {
        fprintf(stderr, "task_name_for_pid() failed: ret: %d mach_error: '%s' errno: %d aka '%s'\n",
                task_name_for_pid_res, mach_error_string(task_name_for_pid_res),
                ctask_name_for_pid_errno, strerror(ctask_name_for_pid_errno));
        return 3;
    }
    printf("self task name:    0x%08x aka %d\n", self_name, self_name);
    puts("");

    ipc_info_space_t space_info          = {0};
    ipc_info_name_array_t table_info     = NULL;
    mach_msg_type_number_t table_infoCnt = 0;
    ipc_info_tree_name_array_t tree_info = NULL;
    mach_msg_type_number_t tree_infoCnt  = 0;
    const int space_info_res             = mach_port_space_info(
        self_regular, &space_info, (ipc_info_name_array_t *)&table_info, &table_infoCnt,
        (ipc_info_tree_name_array_t *)&tree_info, &tree_infoCnt);
    const int cspace_info_errno = errno;
    if (space_info_res != KERN_SUCCESS) {
        fprintf(stderr,
                "mach_port_space_info() failed: ret: %d mach_error: '%s' errno: %d aka '%s'\n",
                space_info_res, mach_error_string(space_info_res), cspace_info_errno,
                strerror(cspace_info_errno));
        return 4;
    }
    printf("table_infoCnt: %u tree_infoCnt: %u\n", table_infoCnt, tree_infoCnt);
    puts("");
    printf("space_info genno_mask: 0x%08x table_next: 0x%08x table_size: 0x%08x tree_hash: 0x%08x "
           "tree_size: 0x%08x tree_small: 0x%08x\n",
           space_info.iis_genno_mask, space_info.iis_table_next, space_info.iis_table_size,
           space_info.iis_tree_hash, space_info.iis_tree_size, space_info.iis_tree_small);
    puts("");
    for (mach_msg_type_number_t i = 0; i < table_infoCnt; ++i) {
        ipc_info_name_t *p = &table_info[i];
        printf("table_info[%3d] name: 0x%08x collision: 0x%08x type: 0x%08X urefs: 0x%08x object: "
               "0x%08x next: 0x%08x hash: 0x%08x\n",
               i, p->iin_name, p->iin_collision, p->iin_type, p->iin_urefs, p->iin_object,
               p->iin_next, p->iin_hash);
    }
    puts("");

    // no surprise that the self_read port doesn't survive execv

    posix_spawnattr_t spawn_attrs;
    posix_spawnattr_init(&spawn_attrs);
    posix_spawnattr_setflags(&spawn_attrs, POSIX_SPAWN_SETEXEC);

    errno         = 0;
    int child_pid = 0;
    int execv_res =
        posix_spawn(&child_pid, prog_path, NULL, &spawn_attrs, (char *const *)argv, environ);
    // int execv_res          = execv(prog_path, (char *const *)argv);

    // should never get here
    const int cexecv_errno = errno;
    posix_spawnattr_destroy(&spawn_attrs);
    printf("res: %d errno: %d aka '%s'", execv_res, cexecv_errno, strerror(cexecv_errno));
    return 4;
}
