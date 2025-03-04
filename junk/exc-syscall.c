#include <mach/arm/boolean.h>
#include <mach/exception_types.h>
#include <mach/mach_traps.h>
#undef NDEBUG
#include <assert.h>

#include <mach/exc.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mach_exc.h"

extern boolean_t mach_exc_trace_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

// Handle EXCEPTION_STATE_IDENTIY behavior
kern_return_t trace_catch_mach_exception_raise_state_identity(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task, exception_type_t exception,
    mach_exception_data_t code, mach_msg_type_number_t code_count, int *flavor,
    thread_state_t old_state, mach_msg_type_number_t old_state_count, thread_state_t new_state,
    mach_msg_type_number_t *new_state_count) {
#pragma unused(exception_port, task, exception, code, code_count, flavor)
    const arm_thread_state64_t *os = (const arm_thread_state64_t *)old_state;
    arm_thread_state64_t *ns       = (arm_thread_state64_t *)new_state;
    const uintptr_t opc            = arm_thread_state64_get_pc(*os);
    fprintf(stderr, "trace_catch_mach_exception_raise_state_identity()\n");
    fprintf(stderr, "opc: %p\n", (void *)opc);
    return KERN_SUCCESS;
}

// Handle EXCEPTION_DEFAULT behavior
extern kern_return_t trace_catch_mach_exception_raise(mach_port_t exception_port,
                                                      mach_port_t thread, mach_port_t task,
                                                      exception_type_t exception,
                                                      mach_exception_data_t code,
                                                      mach_msg_type_number_t code_count) {
#pragma unused(exception_port, thread, task, exception, code, code_count)
    assert(!"catch_mach_exception_raise not to be called");
    return KERN_NOT_SUPPORTED;
}

// Handle EXCEPTION_STATE behavior
extern kern_return_t trace_catch_mach_exception_raise_state(
    mach_port_t exception_port, exception_type_t exception, const mach_exception_data_t code,
    mach_msg_type_number_t code_count, int *flavor, const thread_state_t old_state,
    mach_msg_type_number_t old_state_count, thread_state_t new_state,
    mach_msg_type_number_t *new_state_count) {
#pragma unused(exception_port, exception, code, code_count, flavor, old_state, old_state_count, \
               new_state, new_state_count)
    assert(!"catch_mach_exception_raise_state not to be called");
    return KERN_NOT_SUPPORTED;
}

static void *exc_server_thread(void *arg) {
    fprintf(stderr, "mach_msg_server(mach_exc_trace_server)\n");
    assert(!mach_msg_server(mach_exc_trace_server, MACH_MSG_SIZE_RELIABLE,
                            (mach_port_t)(uintptr_t)arg, 0));
    pthread_exit(NULL);
    abort();
}

static void run_exception_handler(mach_port_t exc_port) {
    pthread_t exc_thread;
    fprintf(stderr, "pthread_create()\n");
    assert(!pthread_create(&exc_thread, NULL, exc_server_thread, (void *)(uintptr_t)exc_port));
    fprintf(stderr, "pthread_detach()\n");
    assert(!pthread_detach(exc_thread));
}

static boolean_t switch_pri_raw(int pri) {
    register int _pri_and_res __asm("w0") = pri;
    __asm__ __volatile("mov x16, %[syscall_num]\n\t"
                       "svc #0x80"
                       : "+w"(_pri_and_res)
                       : [syscall_num] "i"(-59), "w"(_pri_and_res)
                       : "cc");
    return _pri_and_res;
}

static void bad_trap_raw(void) {
    __asm__ __volatile("mov x16, %[syscall_num]\n\t"
                       "svc #0x80"
                       :
                       : [syscall_num] "i"(-133)
                       : "cc");
}

// const uint32_t new_exc_mask = EXC_MASK_SYSCALL | EXC_MASK_MACH_SYSCALL | EXC_MASK_SOFTWARE |
// EXC_MASK_BREAKPOINT | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BAD_ACCESS | EXC_MASK_ALL;
const uint32_t new_exc_mask = EXC_MASK_SYSCALL;

int main(void) {
    const task_port_t self_task          = mach_task_self();
    mach_msg_type_number_t old_exc_count = 1;
    exception_mask_t old_exc_mask;
    mach_port_t orig_exc_port;
    exception_behavior_t orig_exc_behavior;
    thread_state_flavor_t orig_exc_flavor;
    mach_port_t new_exc_port;
    assert(!mach_port_allocate(self_task, MACH_PORT_RIGHT_RECEIVE, &new_exc_port));
    assert(!mach_port_insert_right(self_task, new_exc_port, new_exc_port, MACH_MSG_TYPE_MAKE_SEND));
    const kern_return_t kr_get_exc =
        task_get_exception_ports(self_task, EXC_MASK_SYSCALL, &old_exc_mask, &old_exc_count,
                                 &orig_exc_port, &orig_exc_behavior, &orig_exc_flavor);
    assert(!task_set_exception_ports(self_task, EXC_MASK_SYSCALL, new_exc_port,
                                     (exception_behavior_t)(MACH_EXCEPTION_CODES),
                                     ARM_EXCEPTION_STATE64));
    run_exception_handler(new_exc_port);
    usleep(10000);
    fprintf(stderr, "switch_pri(0)\n");
    swtch_pri(0);
    fprintf(stderr, "switch_pri_raw(0)\n");
    switch_pri_raw(0);
    fprintf(stderr, "bad_trap_raw()\n");
    bad_trap_raw();
    __builtin_trap();
    return 0;
}
