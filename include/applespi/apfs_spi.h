#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <CoreFoundation/CoreFoundation.h>
#include <MacTypes.h>
#include <uuid/uuid.h>

extern OSStatus APFSContainerVolumeGroupGetFirmlinks(const char *disk, uuid_t volume_group_id,
                                                     CFMutableArrayRef *firmlinks);

#ifdef __cplusplus
} // extern "C"
#endif
