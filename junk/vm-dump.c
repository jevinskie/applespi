#include <mach-o/dyld.h>
#include <mach/arm/vm_param.h>
#include <mach/arm/vm_types.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach/vm_types.h>
#include <stdint.h>
#include <stdio.h>

int main() {
    task_t task           = mach_task_self();
    vm_address_t address  = 0;
    uint32_t region_count = 0;
    natural_t depth       = 0;

    while (1) {
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        vm_size_t size;
        kern_return_t kr = vm_region_recurse_64(task, &address, &size, &depth,
                                                (vm_region_recurse_info_t)&info, &count);

        if (kr != KERN_SUCCESS) {
            if (kr == KERN_INVALID_ADDRESS && region_count > 0) {
                printf("Finished scanning address space.\n");
            } else {
                printf("Error: %s\n", mach_error_string(kr));
            }
            break;
        }

        printf("Region %d: 0x%lx - 0x%lx (size: %lu bytes) depth: %u\n", ++region_count, address,
               address + size, size, depth);
        printf("  Protection: %c%c%c\n", (info.protection & VM_PROT_READ) ? 'r' : '-',
               (info.protection & VM_PROT_WRITE) ? 'w' : '-',
               (info.protection & VM_PROT_EXECUTE) ? 'x' : '-');

        if (info.is_submap) {
            depth += 1;
            printf("  Type: submap\n");
        } else {
            if (info.share_mode == SM_COW && info.external_pager) {
                printf("  Type: mapped file\n");
            } else if (info.share_mode == SM_SHARED) {
                printf("  Type: shared memory\n");
            } else if (info.share_mode == SM_PRIVATE) {
                printf("  Type: private memory\n");
            } else if (info.share_mode == SM_EMPTY) {
                printf("  Type: reserved/empty\n");
            } else {
                printf("  Type: other (share_mode: %d)\n", info.share_mode);
            }
        }

        address += size;
    }
    printf("address: 0x%lx VM_MAX_ADDRESS: 0x%lx address > VM_MAX_ADDRESS: %d\n", address,
           VM_MAX_ADDRESS, address > VM_MAX_ADDRESS);

    return 0;
}
