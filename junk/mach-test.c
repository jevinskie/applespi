#include <mach/mach_error.h>
#include <mach/message.h>
#undef NDEBUG
#include <assert.h>

#include <bsm/audit.h>
#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <mach/ndr.h>
#include <mach/task_special_ports.h>
#include <ptrauth.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

// task_identity_token_get_task_port(mach_task_self(), TASK_FLAVOR_NAME, &task_name_port)
//     => mach_msg2_internal(...)
// x0: =>
//        (mach_msg_header_t) {
//            msgh_bits         = 0x00001513
//                => SEND | RCV | SEND_TIMEOUT | RCV_TIMEOUT | RCV_INTERRUPT |
//                RCV_GUARDED_DESC
//            msgh_size         = 0x00000024 36
//            msgh_remote_port  = 0x00000e03 3587
//            msgh_local_port   = 0x00000707 1799
//            msgh_voucher_port = 0x00000000
//            msgh_id           = 0x00000d82 3458
//        }
// x1: 0x0000000200000003
//     => SEND | RCV | SEND_KOBJECT_CALL
// x2: 0x0000002400001513
// x3: 0x0000070700000e03
// x4: 0x00000d8200000000
// x5: 0x0000070700000000
// x6: 0x0000000000000030
// x7: 0x0000000000000000

// Reply:
// x0: =>
//            (mach_msg_header_t) {
//                msgh_bits = 0x80001200
//                    => MSG_STRICT_REPLY | RCV_GUARDED_DESC | COMPLEX
//                msgh_size = 0x00000028 40
//                msgh_remote_port = 0x00000000
//                msgh_local_port = 0x00000707 1799
//                msgh_voucher_port = 0x00000000
//                msgh_id = 0x00000de6 3558 (3458 + 100)
//            }
// x0 + sizeof(mach_msg_header_t) (24) (24): =>
//            (mach_msg_body_t)  (msgh_descriptor_count = 0x00000001)
// x0 + sizeof(mach_msg_header_t) (24) + sizeof(mach_msg_body_t) (4) (28): =>
//            (mach_msg_port_descriptor_t) {
//                name = 0x00001c03 7171
//                pad1 = 0x00000000
//                pad2 = 0x00000000
//                disposition = 0x00000011 MACH_MSG_TYPE_MOVE_SEND
//                type = 0x00000000
//            }

// MACH_MSG_TYPE_MOVE_RECEIVE      16 0x10      Must hold receive right
// MACH_MSG_TYPE_MOVE_SEND         17 0x11      Must hold send right(s)
// MACH_MSG_TYPE_MOVE_SEND_ONCE    18 0x12      Must hold sendonce right
// MACH_MSG_TYPE_COPY_SEND         19 0x13      Must hold send right(s)
// MACH_MSG_TYPE_MAKE_SEND         20 0x14      Must hold receive right
// MACH_MSG_TYPE_MAKE_SEND_ONCE    21 0x15      Must hold receive right
// MACH_MSG_TYPE_COPY_RECEIVE      22 0x16      NOT VALID
// MACH_MSG_TYPE_DISPOSE_RECEIVE   24 0x17      must hold receive right
// MACH_MSG_TYPE_DISPOSE_SEND      25 0x18      must hold send right(s)
// MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26 0x19      must hold sendonce right

#define MACH64_MSG_OPTION_NONE       0x0ull
#define MACH64_SEND_MSG              MACH_SEND_MSG           // 0x00000001
#define MACH64_RCV_MSG               MACH_RCV_MSG            // 0x00000002
#define MACH64_SEND_TIMEOUT          MACH_SEND_TIMEOUT       // 0x00000010
#define MACH64_SEND_OVERRIDE         MACH_SEND_OVERRIDE      // 0x00000020
#define MACH64_SEND_INTERRUPT        MACH_SEND_INTERRUPT     // 0x00000040
#define MACH64_SEND_NOTIFY           MACH_SEND_NOTIFY        // 0x00000080
#define MACH64_RCV_TIMEOUT           MACH_RCV_TIMEOUT        // 0x00000100
#define MACH64_MSG_STRICT_REPLY      MACH_MSG_STRICT_REPLY   // 0x00000200
#define MACH64_RCV_INTERRUPT         MACH_RCV_INTERRUPT      // 0x00000400
#define MACH64_RCV_VOUCHER           MACH_RCV_VOUCHER        // 0x00000800
#define MACH64_RCV_GUARDED_DESC      MACH_RCV_GUARDED_DESC   // 0x00001000
#define MACH64_RCV_SYNC_WAIT         MACH_RCV_SYNC_WAIT      // 0x00004000
#define MACH64_RCV_SYNC_PEEK         MACH_RCV_SYNC_PEEK      // 0x00008000
#define MACH64_SEND_TRAILER          MACH_SEND_TRAILER       // 0x00020000
#define MACH64_SEND_SYNC_OVERRIDE    MACH_SEND_SYNC_OVERRIDE // 0x00100000
//                                   MACH_MSGH_BITS_COMPLEX     0x80000000

#define MACH64_MSG_VECTOR            0x0000000100000000ull
#define MACH64_SEND_KOBJECT_CALL     0x0000000200000000ull
#define MACH64_SEND_MQ_CALL          0x0000000400000000ull
#define MACH64_SEND_ANY              0x0000000800000000ull
#define MACH64_SEND_DK_CALL          0x0000001000000000ull
#define MACH64_PEEK_MSG              0x4000000000000000ull
#define MACH64_MACH_MSG2             0x8000000000000000ull

#define MACH_MSGV_IDX_MSG            ((uint32_t)0)
#define MACH_MSGV_IDX_AUX            ((uint32_t)1)

#define LIBMACH_OPTIONS              (MACH_SEND_INTERRUPT | MACH_RCV_INTERRUPT)
#define LIBMACH_OPTIONS64            (MACH64_SEND_INTERRUPT | MACH64_RCV_INTERRUPT)

#define LIBSYSCALL_MSGV_AUX_MAX_SIZE 128

#define __TSD_MACH_MSG_AUX           123

#define __PTK_LIBDISPATCH_KEY8       28
#define OS_VOUCHER_TSD_KEY           __PTK_LIBDISPATCH_KEY8

#define NDR_RECORD             \
    ((NDR_record_t){           \
        0, /* mig_reserved */  \
        0, /* mig_reserved */  \
        0, /* mig_reserved */  \
        NDR_PROTOCOL_2_0,      \
        NDR_INT_LITTLE_ENDIAN, \
        NDR_CHAR_ASCII,        \
        NDR_FLOAT_IEEE,        \
        0,                     \
    })

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

extern mach_msg_return_t mach_msg2_internal(void *data, mach_msg_option64_t option64,
                                            uint64_t msgh_bits_and_send_size,
                                            uint64_t msgh_remote_and_local_port,
                                            uint64_t msgh_voucher_and_id,
                                            uint64_t desc_count_and_rcv_name,
                                            uint64_t rcv_size_and_priority, uint64_t timeout);

void *dummy_mach_msg2_trap     = mach_msg2_trap;
void *dummy_mach_msg2_internal = mach_msg2_internal;

#ifdef __MigPackStructs
#pragma pack(push, 4)
#endif
typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    task_flavor_t flavor;
} titgtp_req __attribute__((unused));
#ifdef __MigPackStructs
#pragma pack(pop)
#endif

#ifdef __MigPackStructs
#pragma pack(push, 4)
#endif
typedef struct {
    mach_msg_header_t Head;
    /* start of the kernel processed data */
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t task_port;
    /* end of the kernel processed data */
} titgtp_resp __attribute__((unused));
#ifdef __MigPackStructs
#pragma pack(pop)
#endif

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    task_flavor_t flavor;
    mach_msg_trailer_t trailer;
} titgtp_req_trailer __attribute__((unused));

titgtp_req titgtp_req_dummy;
titgtp_resp titgtp_resp_dummy;
titgtp_req_trailer titgtp_req_trailer_dummy;
mach_msg_vector_t mach_msg_vector_dummy;

static void dump_header(const mach_msg_header_t *hdr) {
    printf("mach_msg_header_t        @ %p\n", hdr);
    printf("mach_msg_bits_t          msgh_bits: 0x%08x %u\n", hdr->msgh_bits, hdr->msgh_bits);
    printf("mach_msg_size_t          msgh_size: 0x%08x %u\n", hdr->msgh_size, hdr->msgh_size);
    printf("mach_port_t              msgh_remote_port: 0x%08x %u\n", hdr->msgh_remote_port,
           hdr->msgh_remote_port);
    printf("mach_port_t              msgh_local_port: 0x%08x %u\n", hdr->msgh_local_port,
           hdr->msgh_local_port);
    printf("mach_port_name_t         msgh_voucher_port: 0x%08x %u\n", hdr->msgh_voucher_port,
           hdr->msgh_voucher_port);
    printf("mach_msg_id_t            msgh_id: 0x%08x %d\n", (uint32_t)hdr->msgh_id, hdr->msgh_id);
    fflush(stdout);
}

static void dump_msg_audit_trailer(const mach_msg_audit_trailer_t *trailer) {
    printf("mach_msg_audit_trailer_t @ %p\n", trailer);
    printf("mach_msg_trailer_type_t  msgh_trailer_type: 0x%08x\n", trailer->msgh_trailer_type);
    printf("mach_msg_trailer_size_t  msgh_trailer_size: 0x%08x %u\n", trailer->msgh_trailer_size,
           trailer->msgh_trailer_size);
    printf("mach_port_seqno_t        msgh_seqno: 0x%08x %u\n", trailer->msgh_seqno,
           trailer->msgh_seqno);
    printf("security_token_t         msgh_sender: @ %p\n", &trailer->msgh_sender);
    printf("security_token_t             msgh_sender[0]: UID 0x%08x %u\n",
           trailer->msgh_sender.val[0], trailer->msgh_sender.val[0]);
    printf("security_token_t             msgh_sender[1]: GID 0x%08x %u\n",
           trailer->msgh_sender.val[1], trailer->msgh_sender.val[1]);
    printf("audit_token_t            msgh_audit: @ %p\n", &trailer->msgh_audit);
    printf("audit_token_t                msgh_audit[0]: AuditUID 0x%08x %u\n",
           trailer->msgh_audit.val[0], trailer->msgh_audit.val[0]);
    printf("audit_token_t                msgh_audit[1]: EUID 0x%08x %u\n",
           trailer->msgh_audit.val[1], trailer->msgh_audit.val[1]);
    printf("audit_token_t                msgh_audit[2]: EGID 0x%08x %u\n",
           trailer->msgh_audit.val[2], trailer->msgh_audit.val[2]);
    printf("audit_token_t                msgh_audit[3]: RUID 0x%08x %u\n",
           trailer->msgh_audit.val[3], trailer->msgh_audit.val[3]);
    printf("audit_token_t                msgh_audit[4]: RGID 0x%08x %u\n",
           trailer->msgh_audit.val[4], trailer->msgh_audit.val[4]);
    printf("audit_token_t                msgh_audit[5]: PID 0x%08x %u\n",
           trailer->msgh_audit.val[5], trailer->msgh_audit.val[5]);
    printf("audit_token_t                msgh_audit[6]: AuditSessionID 0x%08x %u\n",
           trailer->msgh_audit.val[6], trailer->msgh_audit.val[6]);
    printf("audit_token_t                msgh_audit[7]: PID Version 0x%08x %u\n",
           trailer->msgh_audit.val[7], trailer->msgh_audit.val[7]);
    fflush(stdout);
}

static void dump_ndr_record(const NDR_record_t *ndr) {
    printf("NDR_record @ %p\n", ndr);
    printf("    mig_vers: %u\n", ndr->mig_vers);
    printf("    if_vers: %u\n", ndr->if_vers);
    printf("    reserved1: %u\n", ndr->reserved1);
    printf("    mig_encoding: %u\n", ndr->mig_encoding);
    printf("    int_rep: %u\n", ndr->int_rep);
    printf("    char_rep: %u\n", ndr->char_rep);
    printf("    float_rep: %u\n", ndr->float_rep);
    printf("    reserved2: %u\n", ndr->reserved2);
    fflush(stdout);
}

static void dump_msg_body(const mach_msg_body_t *body) {
    printf("mach_msg_body_t @ %p\n", body);
    printf("    msgh_descriptor_count: %u\n", body->msgh_descriptor_count);
    fflush(stdout);
}

static void dump_msg_port_desc(const mach_msg_port_descriptor_t *desc) {
    printf("mach_msg_port_descriptor_t @ %p\n", desc);
    printf("    name: 0x%08x %u\n", desc->name, desc->name);
    printf("    pad1: %u\n", desc->pad1);
    printf("    pad2: %u\n", desc->pad2);
    printf("    disposition: %u\n", desc->disposition);
    printf("    type: %u\n", desc->type);
    fflush(stdout);
}

static void dump_task_flavor(const task_flavor_t flavor) {
    assert(flavor < 4);
    printf("task_flavor: %s\n", (const char *[]){"control", "read", "inspect", "name"}[flavor]);
    fflush(stdout);
}

static void dump_msg_trailer(const mach_msg_trailer_t *trailer) {
    printf("mach_msg_trailer_t @ %p\n", trailer);
    printf("    msgh_trailer_size: 0x%08x %u\n", trailer->msgh_trailer_size,
           trailer->msgh_trailer_size);
    printf("    msgh_trailer_type: 0x%08x %u\n", trailer->msgh_trailer_type,
           trailer->msgh_trailer_type);
    fflush(stdout);
}

static void dump_msg_security_trailer(const mach_msg_security_trailer_t *trailer) {
    printf("mach_msg_security_trailer_t @ %p\n", trailer);
    printf("    msgh_trailer_size: 0x%08x %u\n", trailer->msgh_trailer_size,
           trailer->msgh_trailer_size);
    printf("    msgh_trailer_type: 0x%08x %u\n", trailer->msgh_trailer_type,
           trailer->msgh_trailer_type);
    printf("    msgh_seqno: 0x%08x %u\n", trailer->msgh_seqno, trailer->msgh_seqno);
    printf("    msgh_sender[0]: 0x%08x %u\n", trailer->msgh_sender.val[0],
           trailer->msgh_sender.val[0]);
    printf("    msgh_sender[1]: 0x%08x %u\n", trailer->msgh_sender.val[1],
           trailer->msgh_sender.val[1]);
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

    printf("mach_msg2_trap_i0 data: %p options: 0x%016llx\n", data, option64 & ~LIBMACH_OPTIONS64);
    printf("mach_msg2_trap_i0 msgh_bits_and_send_size: 0x%016llx msgh_remote_and_local_port: "
           "0x%016llx\n",
           msgh_bits_and_send_size, msgh_remote_and_local_port);
    printf("mach_msg2_trap_i0 msgh_voucher_and_id: 0x%016llx desc_count_and_rcv_name: "
           "0x%016llx\n",
           msgh_voucher_and_id, desc_count_and_rcv_name);
    printf("mach_msg2_trap_i1 rcv_size_and_priority: 0x%016llx timeout: 0x%016llx\n",
           rcv_size_and_priority, timeout);
    mr = mach_msg2_trap(data, option64 & ~LIBMACH_OPTIONS64, msgh_bits_and_send_size,
                        msgh_remote_and_local_port, msgh_voucher_and_id, desc_count_and_rcv_name,
                        rcv_size_and_priority, timeout);

    if (mr == MACH_MSG_SUCCESS) {
        return MACH_MSG_SUCCESS;
    }

    if ((option64 & MACH64_SEND_INTERRUPT) == 0) {
        while (mr == MACH_SEND_INTERRUPTED) {
            printf("mach_msg2_trap_i1 data: %p options: 0x%016llx\n", data,
                   option64 & ~LIBMACH_OPTIONS64);
            printf("mach_msg2_trap_i1 msgh_bits_and_send_size: 0x%016llx "
                   "msgh_remote_and_local_port: 0x%016llx\n",
                   msgh_bits_and_send_size, msgh_remote_and_local_port);
            printf("mach_msg2_trap_i1 msgh_voucher_and_id: 0x%016llx desc_count_and_rcv_name: "
                   "0x%016llx\n",
                   msgh_voucher_and_id, desc_count_and_rcv_name);
            printf("mach_msg2_trap_i1 rcv_size_and_priority: 0x%016llx timeout: 0x%016llx\n",
                   rcv_size_and_priority, timeout);
            mr = mach_msg2_trap(data, option64 & ~LIBMACH_OPTIONS64, msgh_bits_and_send_size,
                                msgh_remote_and_local_port, msgh_voucher_and_id,
                                desc_count_and_rcv_name, rcv_size_and_priority, timeout);
        }
    }

    if ((option64 & MACH64_RCV_INTERRUPT) == 0) {
        while (mr == MACH_RCV_INTERRUPTED) {
            printf("mach_msg2_trap_i2 data: %p options: 0x%016llx\n", data,
                   my_mach_msg_options_after_interruption(option64));
            printf("mach_msg2_trap_i2 msgh_bits_and_send_size: 0x%016llx "
                   "msgh_remote_and_local_port: 0x%016llx\n",
                   msgh_bits_and_send_size & 0xffffffffull, msgh_remote_and_local_port);
            printf("mach_msg2_trap_i2 msgh_voucher_and_id: 0x%016llx desc_count_and_rcv_name: "
                   "0x%016llx\n",
                   msgh_voucher_and_id, desc_count_and_rcv_name);
            printf("mach_msg2_trap_i2 rcv_size_and_priority: 0x%016llx timeout: 0x%016llx\n",
                   rcv_size_and_priority, timeout);
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
    printf("token_thiny port: 0x%08x %u\n", port, port);
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

    printf("token_thiny port: 0x%08x %u\n", port, port);

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

    task_id_token_t self_task_id_token = MACH_PORT_NULL;
    kr = task_create_identity_token(mach_task_self(), &self_task_id_token);
    printf("self_task_id_token task_create_identity_token: 0x%08x %u\n", self_task_id_token,
           self_task_id_token);
    if (kr != KERN_SUCCESS) {
        printf("self_task_id_token task_create_identity_token failed: 0x%08x a.k.a '%s'\n", kr,
               mach_error_string(kr));
        abort();
    }

    mach_port_t token_reply_port = mig_get_reply_port();
    printf("token_reply_port: 0x%08x %u\n", token_reply_port, token_reply_port);
    assert(token_reply_port != MACH_PORT_NULL);

    struct msg_token_s {
        mach_msg_header_t hdr;
        NDR_record_t ndr;
        task_flavor_t flavor;
    };
    struct msg_token_s msg_token = {};
    memset(&msg_token, 0, sizeof(msg_token));

    struct msg_token_resp_s {
        mach_msg_header_t hdr;
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t task_port;
        mach_msg_audit_trailer_t trailer;
    };
    struct msg_token_resp_s msg_token_reply = {};
    memset(&msg_token_reply, 0, sizeof(msg_token_reply));

    union {
        struct msg_token_s req;
        struct msg_token_resp_s resp;
    } msg_token_mega = {};
    memset(&msg_token_mega, 0, sizeof(msg_token_mega));

    printf("sizeof(msg_token_mega.req): %zu\n", sizeof(msg_token_mega.req));
    printf("sizeof(msg_token_mega.resp): %zu\n", sizeof(msg_token_mega.resp));
    fflush(stdout);

    // msg_token.hdr.msgh_bits             = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
    msg_token_mega.req.hdr.msgh_bits =
        MACH_SEND_MSG | MACH_RCV_MSG | MACH_SEND_TIMEOUT | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT |
        MACH_RCV_GUARDED_DESC | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
    msg_token_mega.req.hdr.msgh_size        = sizeof(msg_token_mega.req);
    msg_token_mega.req.hdr.msgh_id          = 3458;
    msg_token_mega.req.hdr.msgh_local_port  = token_reply_port;
    msg_token_mega.req.hdr.msgh_remote_port = port;
    msg_token_mega.req.ndr                  = NDR_RECORD;
    msg_token_mega.req.flavor               = TASK_FLAVOR_NAME;

    // msg_token.trailer.msgh_trailer_type = MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
    //                                 MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
    //                                 msg_token.trailer.msgh_trailer_size =
    //                                 sizeof(msg_token.trailer);

    // MACH_RCV_MSG | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
    // MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);

    printf("\n\n\n\n");
    printf("msg_token before dumps:\n");
    dump_header(&msg_token_mega.req.hdr);
    // dump_ndr_record(&msg_token_mega.req.ndr);
    dump_task_flavor(msg_token_mega.req.flavor);
    printf("\n\n");
    fflush(stdout);

    // kr = my_mach_msg(&msg_token.hdr, MACH_SEND_MSG, msg_token.hdr.msgh_size, 0, MACH_PORT_NULL,
    // 0, 0);
    kr = my_mach_msg2(&msg_token_mega.req.hdr,
                      MACH64_SEND_MSG | MACH64_RCV_MSG | MACH64_SEND_KOBJECT_CALL |
                          MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                          MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
                      msg_token_mega.req.hdr, msg_token_mega.req.hdr.msgh_size,
                      sizeof(msg_token_mega.resp), msg_token_mega.req.hdr.msgh_local_port, 0,
                      MACH_MSG_PRIORITY_UNSPECIFIED);
    printf("my_mach_msg2 returned %d '%s' msg_token after dumps:\n", kr, mach_error_string(kr));
    dump_header(&msg_token_mega.resp.hdr);
    dump_msg_body(&msg_token_mega.resp.msgh_body);
    // dump_msg_port_desc(&msg_token_mega.resp.task_port);
    printf("dump_msg_trailer(&msg_token_mega.resp.trailer):\n");
    dump_msg_trailer((mach_msg_trailer_t *)&msg_token_mega.resp.trailer);
    printf("dump_msg_trailer((mach_msg_trailer_t *)&msg_token_mega.resp.task_port):\n");
    dump_msg_trailer((mach_msg_trailer_t *)&msg_token_mega.resp.task_port);
    // printf("dump_msg_security_trailer(&msg_token_mega.resp.trailer):\n");
    // dump_msg_security_trailer(&msg_token_mega.resp.trailer);
    // printf("dump_msg_security_trailer((mach_msg_security_trailer_t
    // *)&msg_token_mega.resp.task_port):\n");
    // dump_msg_security_trailer((mach_msg_security_trailer_t *)&msg_token_mega.resp.task_port);
    printf("dump_msg_audit_trailer(&msg_token_mega.resp.trailer):\n");
    dump_msg_audit_trailer(&msg_token_mega.resp.trailer);
    printf("dump_msg_audit_trailer((mach_msg_audit_trailer_t *)&msg_token_mega.resp.task_port):\n");
    dump_msg_audit_trailer((mach_msg_audit_trailer_t *)&msg_token_mega.resp.task_port);
    uint32_t *ptval = (uint32_t *)((uintptr_t)&msg_token_mega.resp +
                                   round_msg(msg_token_mega.resp.hdr.msgh_size));
    printf("trailer: @ %p\n", ptval);
    for (uint32_t i = 0; i < msg_token_mega.resp.trailer.msgh_trailer_size + 32; ++i) {
        printf("trailer[%u]: 0x%08x %u\n", i, ptval[i], ptval[i]);
    }

    // dump_msg_security_trailer(&msg_token_mega.resp.trailer);
    printf("\n\n\n\n");
    fflush(stdout);
    if (kr != KERN_SUCCESS) {
        printf("msg_token mach_msg receive failed: 0x%08x a.k.a '%s'\n", kr, mach_error_string(kr));
        abort();
    }
    // abort();

#if 0
    mach_port_t new_rcv_port = MACH_PORT_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &new_rcv_port);
    printf("new_rcv_port mach_port_allocate: 0x%08x %u\n", new_rcv_port, new_rcv_port);
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

    task_id_token_t self_task_id_token_v2 = MACH_PORT_NULL;
    kr = task_create_identity_token(mach_task_self(), &self_task_id_token_v2);
    printf("self_task_id_token_v2 task_create_identity_token: 0x%08x %u\n", self_task_id_token_v2,
           self_task_id_token_v2);
    if (kr != KERN_SUCCESS) {
        printf("self_task_id_token_v2 task_create_identity_token failed: 0x%08x a.k.a '%s'\n", kr,
               mach_error_string(kr));
        abort();
    }

    mach_port_t self_task_name_port_from_id_token = MACH_PORT_NULL;
    kr = task_identity_token_get_task_port(self_task_id_token_v2, TASK_FLAVOR_NAME,
                                           &self_task_name_port_from_id_token);
    printf("self_task_name_port_from_id_token task_identity_token_get_task_port: 0x%08x %u\n",
           self_task_name_port_from_id_token, self_task_name_port_from_id_token);
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
    memset(&msg, 0, sizeof(msg));
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
    dump_msg_audit_trailer(&msg.trailer);
    printf("\n\n");
    fflush(stdout);

    // kr = my_mach_msg(&msg.hdr, MACH_SEND_MSG, msg.hdr.msgh_size, 0, MACH_PORT_NULL, 0, 0);
    kr = my_mach_msg2(
        &msg.hdr, MACH64_RCV_MSG | MACH64_RCV_TIMEOUT | MACH64_RCV_MSG | MACH64_SEND_KOBJECT_CALL,
        msg.hdr, msg.hdr.msgh_size, msg.trailer.msgh_trailer_size, msg.hdr.msgh_local_port, 1000,
        MACH_MSG_PRIORITY_UNSPECIFIED);
    printf("after dumps:\n");
    dump_header(&msg.hdr);
    dump_msg_audit_trailer(&msg.trailer);
    printf("\n\n\n\n");

    fflush(stdout);
    if (kr != KERN_SUCCESS) {
        printf("mach_msg receive failed: 0x%08x a.k.a '%s'\n", kr, mach_error_string(kr));
        abort();
    }
#endif
}

static void cfi_test_two_bits_set(void) {
    printf("[Crasher]: Try sending mach_msg2() but setting 2 CFI bits\n");

    mach_msg_header_t header;
    kern_return_t kr;

    header.msgh_local_port  = MACH_PORT_NULL;
    header.msgh_remote_port = mach_task_self();
    header.msgh_id          = 3409;
    header.msgh_bits =
        MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, 0);
    header.msgh_size = sizeof(header);

    kr = my_mach_msg2(&header, MACH64_SEND_MSG | MACH64_SEND_KOBJECT_CALL, header, header.msgh_size,
                      0, MACH_PORT_NULL, 0, MACH_MSG_PRIORITY_UNSPECIFIED);
    printf("[Crasher cfi_test_two_bits_set]: mach_msg2() returned %d\n", kr);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: mach-test <child executable to spawn> <child args>");
    }

    printf("sizeof(titgtp_req): %zu\n", sizeof(titgtp_req));
    printf("sizeof(titgtp_resp): %zu\n", sizeof(titgtp_resp));
    printf("sizeof(titgtp_req_trailer): %zu\n", sizeof(titgtp_req_trailer));
    printf("sizeof(mach_msg_vector_t): %zu\n", sizeof(mach_msg_vector_t));

    printf("mach_task_self: 0x%08x %u\n", mach_task_self(), mach_task_self());

    kern_return_t kr;
    mach_port_name_t self_name_port_main = MACH_PORT_NULL;
    kr = task_name_for_pid(mach_task_self(), getpid(), &self_name_port_main);
    if (kr != KERN_SUCCESS) {
        printf("main task_name_for_pid(self) failed: 0x%08x a.k.a '%s'\n", kr,
               mach_error_string(kr));
        abort();
    }
    printf("self_name_port_main: 0x%08x %u\n", self_name_port_main, self_name_port_main);

    pid_t child_pid;
    int child_status;
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
    printf("child_task_name_port task_name_for_pid: 0x%08x %u\n", child_task_name_port,
           child_task_name_port);
    // kr = task_for_pid(mach_task_self(), child_pid, &child_task_name_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to get task port for PID %d: %s\n", child_pid,
                mach_error_string(kr));
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }

    // Create a notification port
    mach_port_t notification_port = MACH_PORT_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notification_port);
    printf("notification_port mach_port_allocate: 0x%08x %u\n", notification_port,
           notification_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate notification port: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), child_task_name_port);
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }

    // Request notification when the task port becomes a dead name
    mach_port_t prev_notif_port = MACH_PORT_NULL;
    kr = mach_port_request_notification(mach_task_self(), child_task_name_port,
                                        MACH_NOTIFY_DEAD_NAME, 0, notification_port,
                                        MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev_notif_port);
    printf("prev_notif_port mach_port_request_notification: 0x%08x %u\n", prev_notif_port,
           prev_notif_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to request notification: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), child_task_name_port);
        mach_port_deallocate(mach_task_self(), notification_port);
        kill(child_pid, SIGKILL); // Kill the suspended child
        return EXIT_FAILURE;
    }

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

    printf("token_thingy(self_name_port_main) run 0\n");
    token_thingy(self_name_port_main);
    printf("token_thingy(self_name_port_main) run 1\n");
    token_thingy(self_name_port_main);
    printf("token_thingy(self_name_port_main) run 1 - DONE\n");

    // Now allow the child to continue
    printf("Resuming child process...\n");
    fflush(stdout);
    kill(child_pid, SIGCONT);

    printf("Waiting for child process (PID %d) to exit...\n", child_pid);

    usleep(1000);

    // token_thingy(mach_task_self());
    // token_thingy(child_task_name_port);
    printf("token_thingy done\n");
    fflush(stdout);

    // Prepare to receive the dead-name notification
    struct {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t port;
        mach_msg_trailer_t trailer;
    } message = {};
    memset(&message, 0, sizeof(message));

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
