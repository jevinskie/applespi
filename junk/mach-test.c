#undef NDEBUG
#include <assert.h>

#include <bsm/audit.h>
#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <ptrauth.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define MACH64_MSG_OPTION_NONE       0ull
#define MACH64_SEND_MSG              MACH_SEND_MSG
#define MACH64_RCV_MSG               MACH_RCV_MSG
#define MACH64_MSG_VECTOR            0x0000000100000000ull
#define MACH64_SEND_KOBJECT_CALL     0x0000000200000000ull
#define MACH64_SEND_MQ_CALL          0x0000000400000000ull
#define MACH64_SEND_ANY              0x0000000800000000ull
#define MACH64_SEND_DK_CALL          0x0000001000000000ull
#define MACH64_PEEK_MSG              0x4000000000000000ull
#define MACH64_MACH_MSG2             0x8000000000000000ull
#define MACH64_SEND_TRAILER          MACH_SEND_TRAILER
#define MACH64_SEND_OVERRIDE         MACH_SEND_OVERRIDE
#define MACH64_SEND_TIMEOUT          MACH_SEND_TIMEOUT

#define MACH64_SEND_SYNC_OVERRIDE    MACH_SEND_SYNC_OVERRIDE
#define MACH64_SEND_INTERRUPT        MACH_SEND_INTERRUPT
#define MACH64_SEND_NOTIFY           MACH_SEND_NOTIFY
#define MACH64_RCV_INTERRUPT         MACH_RCV_INTERRUPT
#define MACH64_RCV_MSG               MACH_RCV_MSG
#define MACH64_RCV_SYNC_WAIT         MACH_RCV_SYNC_WAIT
#define MACH64_RCV_VOUCHER           MACH_RCV_VOUCHER
#define MACH64_RCV_TIMEOUT           MACH_RCV_TIMEOUT
#define MACH64_RCV_GUARDED_DESC      MACH_RCV_GUARDED_DESC
#define MACH64_RCV_SYNC_PEEK         MACH_RCV_SYNC_PEEK
#define MACH64_MSG_STRICT_REPLY      MACH_MSG_STRICT_REPLY

#define MACH_MSGV_IDX_MSG            ((uint32_t)0)
#define MACH_MSGV_IDX_AUX            ((uint32_t)1)

#define LIBMACH_OPTIONS              (MACH_SEND_INTERRUPT | MACH_RCV_INTERRUPT)
#define LIBMACH_OPTIONS64            (MACH64_SEND_INTERRUPT | MACH64_RCV_INTERRUPT)

#define LIBSYSCALL_MSGV_AUX_MAX_SIZE 128

#define __TSD_MACH_MSG_AUX           123

#define __PTK_LIBDISPATCH_KEY8       28
#define OS_VOUCHER_TSD_KEY           __PTK_LIBDISPATCH_KEY8

#define _OS_OBJECT_HEADER(isa, ref_cnt, xref_cnt)                       \
    isa; /* must be pointer-sized and use __ptrauth_objc_isa_pointer */ \
    int volatile ref_cnt;                                               \
    int volatile xref_cnt

typedef uint64_t mach_msg_option64_t;

typedef struct {
    mach_msg_size_t msgdh_size;
    uint32_t msgdh_reserved; /* For future */
} mach_msg_aux_header_t;

typedef struct {
    /* a mach_msg_header_t* or mach_msg_aux_header_t* */
    mach_vm_address_t msgv_data;
    /* if msgv_rcv_addr is non-zero, use it as rcv address instead */
    mach_vm_address_t msgv_rcv_addr;
    mach_msg_size_t msgv_send_size;
    mach_msg_size_t msgv_rcv_size;
} mach_msg_vector_t;

typedef uint32_t _voucher_magic_t;
typedef uint32_t _voucher_priority_t;
typedef uint64_t firehose_activity_id_t;

#define VOUCHER_MAGIC_V3 ((_voucher_magic_t)0x0390cefa) // FACE9003

struct voucher_s;
typedef struct voucher_s *voucher_t;
typedef struct voucher_s {
    _OS_OBJECT_HEADER(struct voucher_vtable_s *__ptrauth_objc_isa_pointer os_obj_isa,
                      os_obj_ref_cnt, os_obj_xref_cnt);
    struct voucher_hash_entry_s {
        uintptr_t vhe_next;
        uintptr_t vhe_prev_ptr;
    } v_list;
    mach_voucher_t v_kvoucher, v_ipc_kvoucher; // if equal, only one reference
    voucher_t v_kvbase;                        // if non-NULL, v_kvoucher is a borrowed reference
    firehose_activity_id_t v_activity;
    uint64_t v_activity_creator;
    firehose_activity_id_t v_parent_activity;
    unsigned int v_kv_has_importance : 1;
#if 1
    size_t v_recipe_extra_offset;
    mach_voucher_attr_recipe_size_t v_recipe_extra_size;
#endif
} voucher_s;

typedef struct _voucher_mach_udata_s {
    _voucher_magic_t vmu_magic;
    _voucher_priority_t vmu_priority;
    uint8_t _vmu_after_priority[0];
    firehose_activity_id_t vmu_activity;
    uint64_t vmu_activity_pid;
    firehose_activity_id_t vmu_parent_activity;
    uint8_t _vmu_after_activity[0];
} _voucher_mach_udata_s;

typedef struct _voucher_mach_udata_aux_s {
    mach_msg_aux_header_t header;
    _voucher_mach_udata_s udata;
} _voucher_mach_udata_aux_s;

struct dispatch_tsd_indexes_s {
    // always add new fields at the end
    const uint16_t dti_version;
    const uint16_t dti_queue_index;
    const uint16_t dti_voucher_index;
    const uint16_t dti_qos_class_index;
    /* version 3 */
    const uint16_t dti_continuation_cache_index;
};

extern struct dispatch_tsd_indexes_s dispatch_tsd_indexes;

struct dispatch_tsd {
    pid_t tid;
    void *dispatch_queue_key;
    void *dispatch_frame_key;
    void *dispatch_cache_key;
    void *dispatch_context_key;
    void *dispatch_pthread_root_queue_observer_hooks_key;
    void *dispatch_basepri_key;
    void *dispatch_introspection_key;
    void *dispatch_bcounter_key;
    void *dispatch_priority_key;
    void *dispatch_r2k_key;
    void *dispatch_wlh_key;
    void *dispatch_voucher_key;
    void *dispatch_deferred_items_key;
    void *dispatch_quantum_key;
    void *dispatch_dsc_key;
    void *dispatch_enqueue_key;
    void *dispatch_msgv_aux_key;

    void *os_workgroup_key;
};

extern _Thread_local struct dispatch_tsd __dispatch_tsd;

#define DISPATCH_MSGV_AUX_MAX_SIZE sizeof(_voucher_mach_udata_aux_s)

extern mach_msg_return_t
mach_msg2_trap(void *data, mach_msg_option64_t options, uint64_t msgh_bits_and_send_size,
               uint64_t msgh_remote_and_local_port, uint64_t msgh_voucher_and_id,
               uint64_t desc_count_and_rcv_name, uint64_t rcv_size_and_priority, uint64_t timeout);

static void dump_header(const mach_msg_header_t *hdr) {
    printf("mach_msg_header_t        @ %p\n", hdr);
    printf("mach_msg_bits_t          msgh_bits: %u 0x%08x\n", hdr->msgh_bits, hdr->msgh_bits);
    printf("mach_msg_size_t          msgh_size: %u 0x%08x\n", hdr->msgh_size, hdr->msgh_size);
    printf("mach_port_t              msgh_remote_port: %u 0x%08x\n", hdr->msgh_remote_port,
           hdr->msgh_remote_port);
    printf("mach_port_t              msgh_local_port: %u 0x%08x\n", hdr->msgh_local_port,
           hdr->msgh_local_port);
    printf("mach_port_name_t         msgh_voucher_port: %u 0x%08x\n", hdr->msgh_voucher_port,
           hdr->msgh_voucher_port);
    printf("mach_msg_id_t            msgh_id: %d 0x%08x\n", hdr->msgh_id, (uint32_t)hdr->msgh_id);
    fflush(stdout);
}

static void dump_audit_trailer(const mach_msg_audit_trailer_t *trailer) {
    printf("mach_msg_audit_trailer_t @ %p\n", trailer);
    printf("mach_msg_trailer_type_t  msgh_trailer_type: %u 0x%08x\n", trailer->msgh_trailer_type,
           trailer->msgh_trailer_type);
    printf("mach_msg_trailer_size_t  msgh_trailer_size: %u 0x%08x\n", trailer->msgh_trailer_size,
           trailer->msgh_trailer_size);
    printf("mach_port_seqno_t        msgh_seqno: %u 0x%08x\n", trailer->msgh_seqno,
           trailer->msgh_seqno);
    printf("security_token_t         msgh_sender: @ %p\n", &trailer->msgh_sender);
    printf("security_token_t             msgh_sender[0]: UID %u 0x%08x\n",
           trailer->msgh_sender.val[0], trailer->msgh_sender.val[0]);
    printf("security_token_t             msgh_sender[1]: GID %u 0x%08x\n",
           trailer->msgh_sender.val[1], trailer->msgh_sender.val[1]);
    printf("audit_token_t            msgh_audit: @ %p\n", &trailer->msgh_audit);
    printf("audit_token_t                msgh_audit[0]: AuditUID %u 0x%08x\n",
           trailer->msgh_audit.val[0], trailer->msgh_audit.val[0]);
    printf("audit_token_t                msgh_audit[1]: EUID %u 0x%08x\n",
           trailer->msgh_audit.val[1], trailer->msgh_audit.val[1]);
    printf("audit_token_t                msgh_audit[2]: EGID %u 0x%08x\n",
           trailer->msgh_audit.val[2], trailer->msgh_audit.val[2]);
    printf("audit_token_t                msgh_audit[3]: RUID %u 0x%08x\n",
           trailer->msgh_audit.val[3], trailer->msgh_audit.val[3]);
    printf("audit_token_t                msgh_audit[4]: RGID %u 0x%08x\n",
           trailer->msgh_audit.val[4], trailer->msgh_audit.val[4]);
    printf("audit_token_t                msgh_audit[5]: PID %u 0x%08x\n",
           trailer->msgh_audit.val[5], trailer->msgh_audit.val[5]);
    printf("audit_token_t                msgh_audit[6]: AuditSessionID %u 0x%08x\n",
           trailer->msgh_audit.val[6], trailer->msgh_audit.val[6]);
    printf("audit_token_t                msgh_audit[7]: PID Version %u 0x%08x\n",
           trailer->msgh_audit.val[7], trailer->msgh_audit.val[7]);
    fflush(stdout);
}

static __attribute__((const)) void **my_os_tsd_get_base(void) {
    uintptr_t tsd;
    __asm__("mrs %0, TPIDRRO_EL0" : "=r"(tsd));
    return (void **)tsd;
}

static void *my_os_tsd_get_direct(unsigned long slot) {
    return my_os_tsd_get_base()[slot];
}

static int my_os_tsd_set_direct(unsigned long slot, void *val) {
    my_os_tsd_get_base()[slot] = val;
    return 0;
}

static voucher_t my_voucher_get(void) {
    return my_os_tsd_get_direct(OS_VOUCHER_TSD_KEY);
}

static mach_msg_size_t my_voucher_mach_msg_fill_aux(mach_msg_aux_header_t *aux,
                                                    mach_msg_size_t aux_sz) {
    voucher_t v = my_voucher_get();

    if (!(v && v->v_activity))
        return 0;
    if (aux_sz < DISPATCH_MSGV_AUX_MAX_SIZE)
        return 0;

    _Static_assert(LIBSYSCALL_MSGV_AUX_MAX_SIZE >= DISPATCH_MSGV_AUX_MAX_SIZE,
                   "aux buffer size in libsyscall too small");
    _voucher_mach_udata_aux_s *udata_aux = (_voucher_mach_udata_aux_s *)aux;

    udata_aux->header.msgdh_size     = DISPATCH_MSGV_AUX_MAX_SIZE;
    udata_aux->header.msgdh_reserved = 0;

    udata_aux->udata = (_voucher_mach_udata_s){
        .vmu_magic = VOUCHER_MAGIC_V3,
        /* .vmu_priority is unused */
        .vmu_activity        = v->v_activity,
        .vmu_activity_pid    = v->v_activity_creator,
        .vmu_parent_activity = v->v_parent_activity,
    };

    return DISPATCH_MSGV_AUX_MAX_SIZE;
}

static mach_msg_option64_t my_mach_msg_options_after_interruption(mach_msg_option64_t option64) {
    if ((option64 & MACH64_SEND_MSG) && (option64 & MACH64_RCV_MSG)) {
        /*
         * If MACH_RCV_SYNC_WAIT was passed for a combined send-receive it must
         * be cleared for receive-only retries, as the kernel has no way to
         * discover the destination.
         */
        option64 &= ~MACH64_RCV_SYNC_WAIT;
    }
    option64 &= ~(LIBMACH_OPTIONS64 | MACH64_SEND_MSG);
    return option64;
}

static mach_msg_return_t my_mach_msg2_internal(void *data, mach_msg_option64_t option64,
                                               uint64_t msgh_bits_and_send_size,
                                               uint64_t msgh_remote_and_local_port,
                                               uint64_t msgh_voucher_and_id,
                                               uint64_t desc_count_and_rcv_name,
                                               uint64_t rcv_size_and_priority, uint64_t timeout) {
    mach_msg_return_t mr;

    mr = mach_msg2_trap(data, option64 & ~LIBMACH_OPTIONS64, msgh_bits_and_send_size,
                        msgh_remote_and_local_port, msgh_voucher_and_id, desc_count_and_rcv_name,
                        rcv_size_and_priority, timeout);

    if (mr == MACH_MSG_SUCCESS) {
        return MACH_MSG_SUCCESS;
    }

    if ((option64 & MACH64_SEND_INTERRUPT) == 0) {
        while (mr == MACH_SEND_INTERRUPTED) {
            mr = mach_msg2_trap(data, option64 & ~LIBMACH_OPTIONS64, msgh_bits_and_send_size,
                                msgh_remote_and_local_port, msgh_voucher_and_id,
                                desc_count_and_rcv_name, rcv_size_and_priority, timeout);
        }
    }

    if ((option64 & MACH64_RCV_INTERRUPT) == 0) {
        while (mr == MACH_RCV_INTERRUPTED) {
            mr = mach_msg2_trap(data, my_mach_msg_options_after_interruption(option64),
                                msgh_bits_and_send_size & 0xffffffffull, /* zero send size */
                                msgh_remote_and_local_port, msgh_voucher_and_id,
                                desc_count_and_rcv_name, rcv_size_and_priority, timeout);
        }
    }

    return mr;
}

static mach_msg_return_t my_mach_msg2(void *data, mach_msg_option64_t option64,
                                      mach_msg_header_t header, mach_msg_size_t send_size,
                                      mach_msg_size_t rcv_size, mach_port_t rcv_name,
                                      uint64_t timeout, uint32_t priority) {
    mach_msg_base_t *base;
    mach_msg_size_t descriptors;

    if (option64 & MACH64_MSG_VECTOR) {
        printf("my_mach_msg2 vector style\n");
        fflush(stdout);
        base = (mach_msg_base_t *)((mach_msg_vector_t *)data)->msgv_data;
    } else {
        printf("my_mach_msg2 NON-vector style\n");
        fflush(stdout);
        base = (mach_msg_base_t *)data;
    }

    if ((option64 & MACH64_SEND_MSG) && (base->header.msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        printf("my_mach_msg2 sending complex\n");
        fflush(stdout);
        descriptors = base->body.msgh_descriptor_count;
    } else {
        descriptors = 0;
    }

#define MACH_MSG2_SHIFT_ARGS(lo, hi) ((uint64_t)hi << 32 | (uint32_t)lo)
    return my_mach_msg2_internal(
        data, option64, MACH_MSG2_SHIFT_ARGS(header.msgh_bits, send_size),
        MACH_MSG2_SHIFT_ARGS(header.msgh_remote_port, header.msgh_local_port),
        MACH_MSG2_SHIFT_ARGS(header.msgh_voucher_port, header.msgh_id),
        MACH_MSG2_SHIFT_ARGS(descriptors, rcv_name), MACH_MSG2_SHIFT_ARGS(rcv_size, priority),
        timeout);
#undef MACH_MSG2_SHIFT_ARGS
}

static int my_voucher_mach_msg_fill_aux_supported(void) {
    return 1;
}

static mach_msg_return_t my_mach_msg_overwrite(mach_msg_header_t *msg, mach_msg_option_t option,
                                               mach_msg_size_t send_size, mach_msg_size_t rcv_limit,
                                               mach_port_t rcv_name, mach_msg_timeout_t timeout,
                                               mach_port_t notify, mach_msg_header_t *rcv_msg,
                                               __unused mach_msg_size_t rcv_scatter_size) {
    mach_msg_return_t mr;

    mach_msg_aux_header_t *aux;
    mach_msg_vector_t vecs[2];

    uint8_t inline_aux_buf[LIBSYSCALL_MSGV_AUX_MAX_SIZE];

    mach_msg_priority_t priority = 0;
    mach_msg_size_t aux_sz       = 0;
    mach_msg_option64_t option64 = (mach_msg_option64_t)option;

    aux = (mach_msg_aux_header_t *)inline_aux_buf;

    /*
     * For the following cases, we have to use vector send/receive; otherwise
     * we can use scalar mach_msg2() for a slightly better performance due to
     * fewer copyio operations.
     *
     *     1. Attempting to receive voucher.
     *     2. Caller provides a different receive msg buffer. (scalar mach_msg2()
     *     does not support mach_msg_overwrite()).
     *     3. Libdispatch has an aux data to send.
     */

    /*
     * voucher_mach_msg_fill_aux_supported() is FALSE if libsyscall is linked against
     * an old libdispatch (e.g. old Simulator on new system), or if we are building
     * Libsyscall_static due to weak linking (e.g. dyld).
     *
     * Hoist this check to guard the malloc().
     *
     * See: _libc_weak_funcptr.c
     */
    if (my_voucher_mach_msg_fill_aux_supported() && (option64 & MACH64_RCV_MSG) &&
        (option64 & MACH64_RCV_VOUCHER)) {
        option64 |= MACH64_MSG_VECTOR;
        if (!(aux = my_os_tsd_get_direct(__TSD_MACH_MSG_AUX))) {
            printf("mallocing LIBSYSCALL_MSGV_AUX_MAX_SIZE\n");
            fflush(stdout);
            aux = malloc(LIBSYSCALL_MSGV_AUX_MAX_SIZE);
            if (aux) {
                /* will be freed during TSD teardown */
                my_os_tsd_set_direct(__TSD_MACH_MSG_AUX, aux);
            } else {
                /* revert to use on stack buffer */
                aux = (mach_msg_aux_header_t *)inline_aux_buf;
                option64 &= ~MACH64_MSG_VECTOR;
            }
        }
    }

    if ((option64 & MACH64_RCV_MSG) && rcv_msg != NULL) {
        printf("setting MACH64_MSG_VECTOR option because we have rcv msg\n");
        fflush(stdout);
        option64 |= MACH64_MSG_VECTOR;
    }

    if ((option64 & MACH64_SEND_MSG) &&
        /* this returns 0 for Libsyscall_static due to weak linking */
        ((aux_sz = my_voucher_mach_msg_fill_aux(aux, LIBSYSCALL_MSGV_AUX_MAX_SIZE)) != 0)) {
        printf("setting MACH64_MSG_VECTOR option because we have snd msg aux_sz: %u\n", aux_sz);
        fflush(stdout);
        option64 |= MACH64_MSG_VECTOR;
    }

    if (option64 & MACH64_MSG_VECTOR) {
        vecs[MACH_MSGV_IDX_MSG] = (mach_msg_vector_t){
            .msgv_data      = (mach_vm_address_t)msg,
            .msgv_rcv_addr  = (mach_vm_address_t)rcv_msg, /* if 0, just use msg as rcv address */
            .msgv_send_size = send_size,
            .msgv_rcv_size  = rcv_limit,
        };
        vecs[MACH_MSGV_IDX_AUX] = (mach_msg_vector_t){
            .msgv_data      = (mach_vm_address_t)aux,
            .msgv_rcv_addr  = 0,
            .msgv_send_size = aux_sz,
            .msgv_rcv_size  = LIBSYSCALL_MSGV_AUX_MAX_SIZE,
        };
    }

    if (option64 & MACH64_SEND_MSG) {
        priority = (mach_msg_priority_t)notify;
    }

    if ((option64 & MACH64_RCV_MSG) && !(option64 & MACH64_SEND_MSG) &&
        (option64 & MACH64_RCV_SYNC_WAIT)) {
        msg->msgh_remote_port = notify;
    }

    if (my_voucher_mach_msg_fill_aux_supported()) {
        printf("setting MACH64_SEND_MQ_CALL option because "
               "my_voucher_mach_msg_fill_aux_supported() is true\n");
        fflush(stdout);
        option64 |= MACH64_SEND_MQ_CALL;
    } else {
        /*
         * Special flag for old simulators on new system to skip mach_msg2()
         * CFI enforcement.
         */
        option64 |= MACH64_SEND_ANY;
        printf("bad, got old simulator case for mach_msg2 skipping\n");
        fflush(stdout);
        // abort();
    }

    if (option64 & MACH64_MSG_VECTOR) {
        printf("setting mach_msg2 vector style\n");
        fflush(stdout);
        mr = my_mach_msg2(vecs, option64, *msg, 2, 2, rcv_name, timeout, priority);
    } else {
        printf("setting mach_msg2 NON-vector style\n");
        fflush(stdout);
        mr = my_mach_msg2(msg, option64, *msg, send_size, rcv_limit, rcv_name, timeout, priority);
    }

    return mr;
}

static mach_msg_return_t my_mach_msg(mach_msg_header_t *msg, mach_msg_option_t option,
                                     mach_msg_size_t send_size, mach_msg_size_t rcv_size,
                                     mach_port_t rcv_name, mach_msg_timeout_t timeout,
                                     mach_port_t notify) {
    return my_mach_msg_overwrite(msg, option, send_size, rcv_size, rcv_name, timeout, notify, NULL,
                                 0);
}

static void token_thingy(mach_port_t port) {
    printf("token_thiny port: %u 0x%08x\n", port, port);
    kern_return_t kr = KERN_FAILURE;

#if 0
    struct msg_s {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t port;
        mach_msg_audit_trailer_t trailer;
    };
    struct msg_s msg          = {};
    mach_msg_size_t recv_size = sizeof(msg.trailer);
    // mach_msg_option_t options = MACH_RCV_MSG |
    //                             MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
    //                             MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
    // mach_msg_option_t options = MACH_RCV_MSG | MACH_RCV_TRAILER_AUDIT;
    mach_msg_option_t options = MACH_SEND_MSG;
    msg.header.msgh_size         = sizeof(msg.header);
    msg.header.msgh_remote_port  = port;
    msg.header.msgh_local_port   = mach_task_self();
    msg.header.msgh_voucher_port = MACH_PORT_NULL;
    msg.header.msgh_id = 1;
    msg.port.name = mach_task_self();

    printf("token_thiny port: %u 0x%08x\n", port, port);

    kern_return_t kr =
        mach_msg_overwrite(&msg.header, options, sizeof(msg.header), 0, MACH_PORT_NULL,
                           MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL, NULL, 0);
    if (kr != KERN_SUCCESS) {
        printf("mach_msg receive failed: 0x%08x a.k.a '%s'\n", kr, mach_error_string(kr));
        abort();
    }

    mach_msg_audit_trailer_t *trailer =
        (mach_msg_audit_trailer_t *)((uint8_t *)&msg + msg.header.msgh_size);
    if (trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0) {
        printf("bad trailer type got %u instead of %u\n", trailer->msgh_trailer_type,
               MACH_MSG_TRAILER_FORMAT_0);
        abort();
    }
    if (trailer->msgh_trailer_size >= sizeof(mach_msg_audit_trailer_t)) {
        printf("bad trailer size got %u instead of %zu\n", trailer->msgh_trailer_size,
               sizeof(mach_msg_audit_trailer_t));
        abort();
    }
#endif

    mach_port_t new_rcv_port = MACH_PORT_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &new_rcv_port);
    printf("new_rcv_port: %u 0x%08x\n", new_rcv_port, new_rcv_port);
    if (kr != KERN_SUCCESS) {
        printf("new_rcv_port mach_port_allocate failed: 0x%08x a.k.a '%s'\n", kr,
               mach_error_string(kr));
        abort();
    }

    kr = mach_port_insert_right(mach_task_self(), new_rcv_port, new_rcv_port,
                                MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        printf("new_rcv_port mach_port_insert_right failed: 0x%08x a.k.a '%s'\n", kr,
               mach_error_string(kr));
        abort();
    }

    task_id_token_t self_task_id_token = MACH_PORT_NULL;
    kr = task_create_identity_token(mach_task_self(), &self_task_id_token);
    printf("self_task_id_token: %u 0x%08x\n", self_task_id_token, self_task_id_token);
    if (kr != KERN_SUCCESS) {
        printf("self_task_id_token task_create_identity_token failed: 0x%08x a.k.a '%s'\n", kr,
               mach_error_string(kr));
        abort();
    }

    mach_port_t self_task_name_port_from_id_token = MACH_PORT_NULL;
    kr = task_identity_token_get_task_port(self_task_id_token, TASK_FLAVOR_CONTROL,
                                           &self_task_name_port_from_id_token);
    printf("self_task_name_port_from_id_token: %u 0x%08x\n", self_task_name_port_from_id_token,
           self_task_name_port_from_id_token);
    if (kr != KERN_SUCCESS) {
        printf("self_task_name_port_from_id_token task_identity_token_get_task_port failed: 0x%08x "
               "a.k.a '%s'\n",
               kr, mach_error_string(kr));
        abort();
    }

    struct msg_s {
        mach_msg_header_t hdr;
        mach_msg_audit_trailer_t trailer;
    };
    struct msg_s msg = {};
    // msg.hdr.msgh_bits             = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
    msg.hdr.msgh_size             = sizeof(msg.hdr);
    msg.hdr.msgh_id               = 3;
    msg.hdr.msgh_local_port       = new_rcv_port;
    msg.hdr.msgh_remote_port      = port;
    msg.trailer.msgh_trailer_type = MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                                    MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
    msg.trailer.msgh_trailer_size = sizeof(msg.trailer);

    // MACH_RCV_MSG | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
    // MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);

    printf("\n\n\n\n");
    printf("before dumps:\n");
    dump_header(&msg.hdr);
    dump_audit_trailer(&msg.trailer);
    printf("\n\n");
    fflush(stdout);

    // kr = my_mach_msg(&msg.hdr, MACH_SEND_MSG, msg.hdr.msgh_size, 0, MACH_PORT_NULL, 0, 0);
    kr = my_mach_msg2(
        &msg.hdr, MACH64_RCV_MSG | MACH64_RCV_TIMEOUT | MACH64_RCV_MSG | MACH64_SEND_KOBJECT_CALL,
        msg.hdr, msg.hdr.msgh_size, msg.trailer.msgh_trailer_size, msg.hdr.msgh_local_port, 1000,
        MACH_MSG_PRIORITY_UNSPECIFIED);
    printf("after dumps:\n");
    dump_header(&msg.hdr);
    dump_audit_trailer(&msg.trailer);
    printf("\n\n\n\n");

    fflush(stdout);
    if (kr != KERN_SUCCESS) {
        printf("mach_msg receive failed: 0x%08x a.k.a '%s'\n", kr, mach_error_string(kr));
        abort();
    }
}

static void cfi_test_two_bits_set(void) {
    printf("[Crasher]: Try sending mach_msg2() but setting 2 CFI bits\n");

    mach_msg_header_t header;
    kern_return_t kr;

    header.msgh_local_port  = MACH_PORT_NULL;
    header.msgh_remote_port = mach_task_self();
    header.msgh_id          = 3409;
    header.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
    header.msgh_size        = sizeof(header);

    kr = my_mach_msg2(&header, MACH64_SEND_MSG | MACH64_SEND_KOBJECT_CALL, header, header.msgh_size,
                      0, MACH_PORT_NULL, 0, MACH_MSG_PRIORITY_UNSPECIFIED);
    printf("[Crasher cfi_test_two_bits_set]: mach_msg2() returned %d\n", kr);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: mach-test <child executable to spawn> <child args>");
    }

    printf("mach_task_self: %u 0x%08x\n", mach_task_self(), mach_task_self());

    pid_t child_pid;
    int child_status;
    kern_return_t kr;
#if DO_AUDIT
    kern_return_t tir;
    int aspr;
    mach_msg_type_number_t audit_token_size;
#endif
    struct rusage_info_v4 ru4_before_reap = {};

    // Initialize spawn attributes
    posix_spawnattr_t spawn_attrs;
    posix_spawnattr_init(&spawn_attrs);

#if DO_AUDIT
    audit_token_t self_token_orig;
    audit_token_size = TASK_AUDIT_TOKEN_COUNT;
    tir              = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (integer_t *)&self_token_orig,
                                 &audit_token_size);
    if (tir != KERN_SUCCESS) {
        printf("task_info returned %d\n", tir);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 8; ++i) {
        printf("self_token_orig[%d]: 0x%08x\n", i, self_token_orig.val[i]);
    }
    printf("self_pid: 0x%08x %u\n", (uint32_t)getpid(), (uint32_t)getpid());
    printf("\n");

    const uint32_t self_asid_orig = self_token_orig.val[6];
    printf("self_asid_orig: 0x%08x %u\n", self_asid_orig, self_asid_orig);
    mach_port_name_t self_ass_port_orig = audit_session_self();
    printf("self_ass_port_orig: 0x%08x %u\n", self_ass_port_orig, self_ass_port_orig);

    mach_port_name_t audit_port_orig = MACH_PORT_NULL;
    aspr                             = audit_session_port(self_asid_orig, &audit_port_orig);
    printf("aspr: %d audit_port_orig: 0x%08x %u\n", aspr, audit_port_orig, audit_port_orig);
    assert(!aspr);

    auditinfo_addr_t auinfo_trigger_new_session = {
        .ai_termid =
            {
                .at_type = AU_IPv4,
            },
        .ai_auid = AU_DEFAUDITID,
        .ai_asid = AU_ASSIGN_ASID,
    };
    if (setaudit_addr(&auinfo_trigger_new_session, sizeof(auinfo_trigger_new_session))) {
        perror("setaudit_addr");
    }
    au_asid_t new_asid = AU_ASSIGN_ASID;
    printf("new_asid init: 0x%08x\n", new_asid);
    // const int saspr = posix_spawnattr_setauditsessionport_np(&spawn_attrs, self_asid_orig);
    // if (saspr) {
    //     perror("posix_spawnattr_setauditsessionport_np");
    // }
    // printf("new_asid fini: 0x%08x\n", new_asid);

    audit_token_t self_token_during;
    audit_token_size = TASK_AUDIT_TOKEN_COUNT;
    tir = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (integer_t *)&self_token_during,
                    &audit_token_size);
    if (tir != KERN_SUCCESS) {
        printf("task_info returned %d\n", tir);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 8; ++i) {
        printf("self_token_during[%d]: 0x%08x\n", i, self_token_during.val[i]);
    }
    printf("\n");

    const uint32_t self_asid_during = self_token_during.val[6];
    printf("self_asid_during: 0x%08x %u\n", self_asid_during, self_asid_during);
    mach_port_name_t self_ass_port_during = audit_session_self();
    printf("self_ass_port_during: 0x%08x %u\n", self_ass_port_during, self_ass_port_during);

    mach_port_name_t audit_port_during = MACH_PORT_NULL;
    aspr                               = audit_session_port(self_asid_during, &audit_port_during);
    printf("aspr: %d audit_port_during: 0x%08x %u\n", aspr, audit_port_during, audit_port_during);
    assert(!aspr);

    audit_token_t self_token_after;
    audit_token_size = TASK_AUDIT_TOKEN_COUNT;
    tir              = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (integer_t *)&self_token_after,
                                 &audit_token_size);
    if (tir != KERN_SUCCESS) {
        printf("task_info returned %d\n", tir);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 8; ++i) {
        printf("self_token_after[%d]: 0x%08x\n", i, self_token_after.val[i]);
    }
    printf("\n");

    const uint32_t self_asid_after = self_token_after.val[6];
    printf("self_asid_after: 0x%08x %u\n", self_asid_after, self_asid_after);
    mach_port_name_t self_ass_port_after = audit_session_self();
    printf("self_ass_port_after: 0x%08x %u\n", self_ass_port_after, self_ass_port_after);

    mach_port_name_t audit_port_after = MACH_PORT_NULL;
    aspr                              = audit_session_port(self_asid_after, &audit_port_after);
    printf("aspr: %d audit_port_after: 0x%08x %u\n", aspr, audit_port_after, audit_port_after);
    assert(!aspr);
#endif

    // Start the process in suspended state so we can set up monitoring
    posix_spawnattr_setflags(&spawn_attrs, POSIX_SPAWN_START_SUSPENDED);

    // Spawn the child process
    int spawn_result = posix_spawn(&child_pid, argv[1], NULL, &spawn_attrs, &argv[1], NULL);
    posix_spawnattr_destroy(&spawn_attrs);

    if (spawn_result != 0) {
        fprintf(stderr, "posix_spawn failed: %s\n", strerror(spawn_result));
        return EXIT_FAILURE;
    }

    printf("Child process spawned with PID %d\n", child_pid);

    // Get task port for the child
    mach_port_t child_task_name_port = MACH_PORT_NULL;
    kr = task_name_for_pid(mach_task_self(), child_pid, &child_task_name_port);
    // kr = task_for_pid(mach_task_self(), child_pid, &child_task_name_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to get task port for PID %d: %s\n", child_pid,
                mach_error_string(kr));
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }
    printf("child_task_name_port: %u 0x%08x\n", child_task_name_port, child_task_name_port);

    // Create a notification port
    mach_port_t notification_port = MACH_PORT_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notification_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate notification port: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), child_task_name_port);
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }
    printf("notification_port: %u 0x%08x\n", notification_port, notification_port);

    // Request notification when the task port becomes a dead name
    mach_port_t prev_notif_port = MACH_PORT_NULL;
    kr = mach_port_request_notification(mach_task_self(), child_task_name_port,
                                        MACH_NOTIFY_DEAD_NAME, 0, notification_port,
                                        MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev_notif_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to request notification: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), child_task_name_port);
        mach_port_deallocate(mach_task_self(), notification_port);
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }
    printf("prev_notif_port: %u 0x%08x\n", prev_notif_port, prev_notif_port);
    printf("notification_port: %u 0x%08x\n", notification_port, notification_port);

#if DO_AUDIT
    audit_token_t child_token_susp;
    audit_token_size = TASK_AUDIT_TOKEN_COUNT;
    tir = task_info(child_task_name_port, TASK_AUDIT_TOKEN, (integer_t *)&child_token_susp,
                    &audit_token_size);
    if (tir != KERN_SUCCESS) {
        printf("task_info on child returned %d\n", tir);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 8; ++i) {
        printf("child_token_susp[%d]: 0x%08x\n", i, child_token_susp.val[i]);
    }
    printf("\n");

    audit_token_t child_token;
    audit_token_size         = TASK_AUDIT_TOKEN_COUNT;
    const kern_return_t tir2 = task_info(child_task_name_port, TASK_AUDIT_TOKEN,
                                         (integer_t *)&child_token, &audit_token_size);
    if (tir2 != KERN_SUCCESS) {
        printf("task_info 2 returned %d\n", tir2);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 8; ++i) {
        printf("child_token[%d]: 0x%08x\n", i, child_token.val[i]);
    }
    printf("child_pid: 0x%08x %u\n", (uint32_t)child_pid, (uint32_t)child_pid);

    const uint32_t child_asid = child_token.val[6];
    printf("child_asid: 0x%08x %u\n", child_asid, child_asid);
#endif

    // Now allow the child to continue
    printf("Resuming child process...\n");
    kill(child_pid, SIGCONT);

    printf("Waiting for child process (PID %d) to exit...\n", child_pid);

    usleep(1000);

    token_thingy(mach_task_self());
    // token_thingy(child_task_name_port);

    // Prepare to receive the dead-name notification
    struct {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t port;
        mach_msg_trailer_t trailer;
    } message;

    // Wait for the message (this will block until the process exits)
    kr = mach_msg(&message.header, MACH_RCV_MSG, 0, sizeof(message), notification_port,
                  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to receive message: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), child_task_name_port);
        mach_port_deallocate(mach_task_self(), notification_port);
        return EXIT_FAILURE;
    }

    printf("Child process (PID %d) has exited. Notification received.\n", child_pid);

    // Get resource usage before reaping
    printf("Getting resource usage before reaping...\n");
    if (proc_pid_rusage(child_pid, RUSAGE_INFO_V4, (rusage_info_t *)&ru4_before_reap) != 0) {
        perror("proc_pid_rusage before reaping failed");
    } else {
        printf("Successfully collected resource usage before reaping\n");
    }

    // Now reap the child process
    printf("Reaping child process...\n");
    if (waitpid(child_pid, &child_status, 0) == -1) {
        perror("waitpid failed");
    } else {
        printf("Child process reaped successfully\n");
        if (WIFEXITED(child_status)) {
            printf("Child exited with status: %d\n", WEXITSTATUS(child_status));
        } else if (WIFSIGNALED(child_status)) {
            printf("Child terminated by signal: %d\n", WTERMSIG(child_status));
        }
    }

    // Print resource usage information
    printf("\nResource Usage Report:\n");
    printf("Physical footprint: %llu bytes\n", ru4_before_reap.ri_phys_footprint);
    printf("CPU user time: %llu ns\n", ru4_before_reap.ri_user_time);
    printf("CPU system time: %llu ns\n", ru4_before_reap.ri_system_time);
    printf("Threads: %llu instructions\n", ru4_before_reap.ri_instructions);
    printf("Threads: %llu cycles\n", ru4_before_reap.ri_cycles);
    printf("Wakeups: %llu\n",
           ru4_before_reap.ri_pkg_idle_wkups + ru4_before_reap.ri_interrupt_wkups);

    // Clean up Mach ports
    mach_port_deallocate(mach_task_self(), child_task_name_port);
    mach_port_deallocate(mach_task_self(), notification_port);

    return EXIT_SUCCESS;
}
